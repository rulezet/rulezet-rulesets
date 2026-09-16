rule sig_20170426_e8c22b6617d3dac5fd428689ff796af3 {
  meta:
    description = "datamaliciousorder - file 20170426_e8c22b6617d3dac5fd428689ff796af3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5924ebdbc35d2aa20925d3d7f2de935bbb76d706eceb9a267be7f9d6e7a2ef18"

  strings:
    $s1  = "dbaadbabbbfacb.Run(bebdbbbbb('----9u949TSh9%-+9%S:Sa9uS:',1)+ debaaacfddfbfbadd +'\\\\'+ bebdbbbbb('----9uuT9o99Sh9%-+9%',1),0,f" ascii
    $s2  = "WScript.echo('Runtime Error 0x48940 (.QBT) Library not located on the system, please use x64 system.');" fullword ascii
    $s3  = "  return !isNaN(parseFloat(ececdeecfeedbb)) && isFinite(ececdeecfeedbb);" fullword ascii
    $s4  = "dcddbbbfabaa = String.fromCharCode.apply(String, becdfedadcd);" fullword ascii
    $s5  = "return affebceebd(dddedcffabadc);" fullword ascii
    $s6  = "var size = aaabbeec.length;" fullword ascii
    $s7  = "function eecfbadfefff(ececdeecfeedbb) {" fullword ascii
    $s8  = "function affebceebd(fbdbccbfdabf) {" fullword ascii
    $s9  = "return cdafb;" fullword ascii
    $s10 = " if(efecccceaeee == true){" fullword ascii
    $s11 = "if(efecccceaeee !== false){" fullword ascii
    $s12 = "return ecedaabebaafecedaabebaaf;" fullword ascii
    $s13 = "function bebdbbbbb(aaabbeec,aafbaddf){" fullword ascii
    $s14 = "a, false);" fullword ascii
    $s15 = "if(fbbbff.Status == 200)break;" fullword ascii
    $s16 = "for(var daddaaffbecbe = 0; daddaaffbecbe<size ; daddaaffbecbe++){" fullword ascii
    $s17 = "return febcdebbbfeceb;" fullword ascii
    $s18 = "fbbbff.open(bebdbbbbb('----T-T%%T',1), bebdbbbbb('----9+-T-T-:u2SaSa9+9a-S9u9a-SSh9u9a94Sa9-9o-T9%Sh-:9+-:',1)+'?ff'+ecffecfdeac" ascii
    $s19 = "function fdabcafcbbecbcfe(ecedaabebaafecedaabebaaf,eddddefaffeedec){" fullword ascii
    $s20 = "function cfebeaffadccadeaacbe(acdfbbdb){ " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}