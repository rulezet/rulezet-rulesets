rule mime_mso_embedded_ole
{
meta:
    comment = "mime mso office obfuscation"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "@mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "docOleData"
    $b = "binData"
    $c = "schemas.microsoft.com"

condition:
    all of them
}