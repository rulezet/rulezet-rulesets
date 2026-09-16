rule _media_brian_88D1_7DB91_infected_07_14_18_Tryag_File_Manager_jpeg_master_up {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file up.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "5bdaa9018e5892715d584d359f2d7eafd528137ec1ac403aafd56662e4bece05"

  strings:
    $s1 = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
    $s2 = "if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo '<b>Shell Uploaded ! :)<b><br><br>'; }" fullword ascii
    $s3 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
    $s4 = "if( $_POST['_upl'] == \"Upload\" ) {" fullword ascii
    $s5 = "else { echo '<b>Not uploaded ! </b><br><br>'; }" fullword ascii

  condition:
    (uint16(0) == 0x743c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}