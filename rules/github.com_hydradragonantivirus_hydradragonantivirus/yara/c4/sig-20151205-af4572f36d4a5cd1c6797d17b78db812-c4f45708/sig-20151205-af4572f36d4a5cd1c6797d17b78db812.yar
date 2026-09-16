rule sig_20151205_af4572f36d4a5cd1c6797d17b78db812 {
  meta:
    description = "datamaliciousorder - file 20151205_af4572f36d4a5cd1c6797d17b78db812.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae08aded658ac2f9d9180cea51963d6cc01caf69457eae99f4c7d27a8cba1859"

  strings:
    $s1 = "var str=\"5553565E0D0A020B24011C1405101001070C4A070B095E3C5E010A080D030C10010A09010A10170107160110174A070B095E17565E5550505D5653" ascii
    $s2 = "false';var o5='GET\",';var z7='spon';var q5=' n';var e1='46';var a7='10';var p1='\".sp';var j5=' (xo';var f3='m\"';var z6='on ';" ascii
    $s3 = " b1='\")';var x7='ea';var t3='ip';var t8='= ';function a3(){return y5;};var r1='(er) ';var g3='';var y5=eval;var u2='';var b4='A" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}