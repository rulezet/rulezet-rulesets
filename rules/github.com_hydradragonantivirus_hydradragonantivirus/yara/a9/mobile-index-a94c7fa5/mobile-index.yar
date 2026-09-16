rule mobile_index {
    meta:
        description = "Chinese Hacktool Set - file index.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "353239a2116385aa2036a9748b8d2e9b7454bede"
    strings:
        $s0 = "$c = @mssql_connect($_POST['datasource'],$_POST['username'],$_POST['password']) " ascii
        $s1 = "<form name=\"form1\" method=\"post\" action=\"index.php\">" fullword ascii
        $s2 = "$_SESSION['datasource_password'] = $_POST['password'];" fullword ascii
        $s3 = "<b>Username:</b>" fullword ascii
    condition:
        filesize < 21KB and all of them
}