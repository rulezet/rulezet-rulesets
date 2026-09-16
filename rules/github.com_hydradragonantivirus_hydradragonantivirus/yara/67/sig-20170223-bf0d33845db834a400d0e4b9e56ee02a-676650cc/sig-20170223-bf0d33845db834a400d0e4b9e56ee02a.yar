rule sig_20170223_bf0d33845db834a400d0e4b9e56ee02a {
  meta:
    description = "datamaliciousorder - file 20170223_bf0d33845db834a400d0e4b9e56ee02a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c343ad743d46546b3b5e7f44cbb3a96b49e8d426df9122d5ac75cd462e124ff"

  strings:
    $s1 = "var x = new Array(\"avivamientohoy.com\", \"richmondyachtbasin.com\", \"nspiredphotography.com\", \"mvtrading.net\", \"powerofat" ascii
    $s2 = "var x = new Array(\"avivamientohoy.com\", \"richmondyachtbasin.com\", \"nspiredphotography.com\", \"mvtrading.net\", \"powerofat" ascii
    $s3 = "e.open(\"GE\"+\"T\", t4 + \":/\"+ter+x[i]+\"/c\"+\"ounter/?\"+m, false);" fullword ascii
    $s4 = "return new ActiveXObject(g2);" fullword ascii
    $s5 = "var vDJmB = function(){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}