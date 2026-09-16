rule sig_20170304_810b89ab9772b0c5f2d1bd8a8963499a {
  meta:
    description = "datamaliciousorder - file 20170304_810b89ab9772b0c5f2d1bd8a8963499a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a17a46ebf12ffbe901b7262b1a71f8094d26cb4437c5d7a0924b245c88ed9f6"

  strings:
    $s1 = "var x = new Array(\"tryitontechnology.com\", \"cravecraa.com\", \"jleaf.se\", \"writewhenyougetwork.com\", \"womenwithpromise.or" ascii
    $s2 = "e[raspbna2s[9-9+0]](\"G\"+\"\"+\"\"+hfpi+\"\"+\"T\", t4 + \":\"+ter+ter+x[i]+ter+\"c\"+\"o\"+\"u\"+\"n\"+\"t\"+\"er/?\"+m,false)" ascii
    $s3 = "return new ActiveXObject(g2);" fullword ascii
    $s4 = "var vDJmB = function(){" fullword ascii
    $s5 = "function mesuto() {" fullword ascii
    $s6 = "function reqty(fdga) { eval(fdga); }" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}