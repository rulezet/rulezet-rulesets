rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_my_ID_id {
  meta:
    description = "case127 - file id.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "7b757ad189977023f5e9d940284a5c5840f20f9b744c1656341663bf9b80d7fc"

  strings:
    $s1  = "<form action=\"ID/identity/mail/identity.php\" method=\"post\" enctype=\"multipart/form-data\" onsubmit=\"return ray.ajax()\">" fullword ascii
    $s2  = "<font color=\"#05285c\"> <font id=\"overpanel-header\">  You need documents to prove your identity. </font> </font>" fullword ascii
    $s3  = "<div id=\"load\" class=\"transitioning spinner spin\" style=\"display:none;\">Processing of your documents...</div>" fullword ascii
    $s4  = "<script type=\"text/javascript\" src=\"identity/ds/jquery.min.js\"></script>" fullword ascii
    $s5  = "lblError.html(\"Attach copy of the official document\" );" fullword ascii
    $s6  = "lblError.html(\"Attach copy of the Credit Card (front & back)\" );" fullword ascii
    $s7  = "<div  style=\"height: 0px;\"> <span id=\"lblError2\" class=\"message\"   ></span>  <span  id=\"message1\" ></span> </div>" fullword ascii
    $s8  = "<div  style=\"height: 0px;\"> <span id=\"lblError1\" class=\"message\"   ></span>  <span  id=\"message1\" ></span> </div>" fullword ascii
    $s9  = "<img style=\"height: 116px;width: 278px;\" src=\"./ID/identity/images/card.png\">" fullword ascii
    $s10 = "()])+(\" + allowedFiles.join('|') + \")$\");" fullword ascii
    $s11 = "<input class=\"aaa\"    value=\"Attach copy of the Credit Card\" readonly=\"readonly\" style=\"width: 280px; height: 40px\" />" fullword ascii
    $s12 = "lblError.html('');" fullword ascii
    $s13 = "<img src=\"./ID/identity/images/identity.png\">" fullword ascii
    $s14 = "$(\"body\").on(\"click\", \"#btnUpload\", function () {" fullword ascii
    $s15 = "var lblError = $(\"#lblError2\");" fullword ascii
    $s16 = "var lblError = $(\"#lblError1\");" fullword ascii
    $s17 = "if (!regex.test(fileUpload.val().toLowerCase())) {" fullword ascii

  condition:
    (uint16(0) == 0x213c and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}