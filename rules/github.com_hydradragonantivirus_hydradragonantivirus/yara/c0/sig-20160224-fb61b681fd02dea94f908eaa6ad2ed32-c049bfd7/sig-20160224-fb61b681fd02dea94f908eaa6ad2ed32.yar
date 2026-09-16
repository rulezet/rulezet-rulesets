rule sig_20160224_fb61b681fd02dea94f908eaa6ad2ed32 {
  meta:
    description = "datamaliciousorder - file 20160224_fb61b681fd02dea94f908eaa6ad2ed32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b864ec7ecd1bef5571aa9b0f4ef12e2a33724acbd3d2ec98dc8145ece56a9aa"

  strings:
    $s1 = "    var trothAd7 = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "        return WScript[unanimityJTz](anodyneBWN);" fullword ascii
    $s3 = "var manifestationBcs = function() {" fullword ascii
    $s4 = "function btoa(chaffYey, gainsayuPu, nonplusR3z, overweeningvDa, gainsayf35, amenableKIq, weighXBS, augustQ5c) {" fullword ascii
    $s5 = "var grudgingjpy = function(inclinedgW8) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}