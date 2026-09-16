rule table_export_download {
    meta:
        description = "Chinese Hacktool Set - file table_export_download.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "2758e553d1059bdbc4e3993dd6f46218fc26103d"
    strings:
        $s0 = "header('Content-Disposition: attachment; filename=\"' . $_SESSION['database'] . " ascii
        $s1 = "header('Content-Length: ' . strlen($_POST['data']));" fullword ascii
        $s2 = "header('Content-type: application/x-download');" fullword ascii
        $s3 = "echo $_POST['data'];" fullword ascii
    condition:
        filesize < 5KB and all of them
}