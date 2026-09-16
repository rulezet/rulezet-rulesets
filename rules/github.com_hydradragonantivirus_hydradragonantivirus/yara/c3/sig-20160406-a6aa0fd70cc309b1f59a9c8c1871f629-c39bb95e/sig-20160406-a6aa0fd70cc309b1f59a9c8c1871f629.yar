rule sig_20160406_a6aa0fd70cc309b1f59a9c8c1871f629 {
  meta:
    description = "datamaliciousorder - file 20160406_a6aa0fd70cc309b1f59a9c8c1871f629.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d39932617a13230f5b0c56305adbe2fc75c7261a04c74acc42ca8c9478edcf8d"

  strings:
    $s1 = "//  var fn = ws.ExpandEnvironmentStrings(\"%TEMP%\") + String.fromCharCode(92) + fn;" fullword ascii
    $s2 = "//  xo.onreadystatechange = function (){" fullword ascii
    $s3 = "//    xo.open(\"GET\", fr, false);" fullword ascii
    $s4 = "//  catch (er){  }  ;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}