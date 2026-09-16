rule sig_20160523_6f9b457ba2a7837be2085361903f44e7 {
  meta:
    description = "datamaliciousorder - file 20160523_6f9b457ba2a7837be2085361903f44e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c95ff58c753a5aa1ce015137586ba65527323df89704cc8986d3f0360a1a2006"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "            var fileObj = fso.GetFile(filename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check" ascii
    $s3 = " = ts.ReadAll();                 eval(check);                               ts.Close();                     }                mai" ascii
    $s4 = "oKGUpe307ICAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdh" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}