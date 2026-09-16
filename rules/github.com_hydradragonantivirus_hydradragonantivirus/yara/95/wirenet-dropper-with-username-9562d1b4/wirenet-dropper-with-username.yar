rule wirenet_dropper_with_username {
  meta:
    description = "Wirenet backdoor dropper Invoice_SKMBT_20170601.doc with username"
    author      = "Chris Rogers"
    company     = "Cyberdefenses, Inc."
    date        = "2017-07-11"
    hash        = "954d7c15577f118171cc8adcc9f9ac94"

  strings:
    $a = /C:\\Users\\[A-Za-z0-9_]+\\Desktop\\JAVA\\docinvoice.exe/
    $b = /C:\\Users\\[A-Za-z0-9_]+\\AppData\\Local\\Temp\\docinvoice.exe/
    $c = "ZTUWVSPRTj"
    $d = "IE(AL(\"%s\",4),AL(\"%0:s\",3)"

  condition:
    all of them
}