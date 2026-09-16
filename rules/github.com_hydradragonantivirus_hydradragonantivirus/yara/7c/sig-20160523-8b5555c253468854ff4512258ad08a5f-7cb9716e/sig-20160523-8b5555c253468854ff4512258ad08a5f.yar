rule sig_20160523_8b5555c253468854ff4512258ad08a5f {
  meta:
    description = "datamaliciousorder - file 20160523_8b5555c253468854ff4512258ad08a5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc70bf2846bb15c877a8c027862e7d41860d3469b2bd1c94e711c5cb5c06ff75"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "           var check = ts.ReadAll();                 eval(check);                               ts.Close();                     " ascii
    $s3 = "2YS5leGUnLCAxKX1jYXRjaChlKXt9OyAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}