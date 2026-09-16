rule sig_20160523_f3909c6e5761ec9f66607a755db9cff5 {
  meta:
    description = "datamaliciousorder - file 20160523_f3909c6e5761ec9f66607a755db9cff5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d64e51f01286d85cdd87a12ad796de75f2d7f93644bc165fac1bf6e16f4ebe35"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "            var fileObj = fso.GetFile(filename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check" ascii
    $s3 = " = ts.ReadAll();                 eval(check);                               ts.Close();                     }                mai" ascii
    $s4 = "oKGUpe307ICAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdh" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}