rule sig_20160523_41119a34d9d41a99677bea53e2100f96 {
  meta:
    description = "datamaliciousorder - file 20160523_41119a34d9d41a99677bea53e2100f96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54ac38491882bab2fce9ff70ec546a1afcf35618c1c280ce51ef790d2c76eaef"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "GetFile(filename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();              " ascii
    $s3 = "gIC';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdhjashdjhs5 + ashdjahsdjh6 + dsf" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}