rule sig_20160523_05156453292f93094371e73fdbfb9242 {
  meta:
    description = "datamaliciousorder - file 20160523_05156453292f93094371e73fdbfb9242.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95df991a43148b2ba6a21fa0f4988880f626d631a73057c98be2d66fed059de2"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "           var check = ts.ReadAll();                 eval(check);                               ts.Close();                     " ascii
    $s3 = "2Ni5leGUnLCAxKX1jYXRjaChlKXt9OyAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}