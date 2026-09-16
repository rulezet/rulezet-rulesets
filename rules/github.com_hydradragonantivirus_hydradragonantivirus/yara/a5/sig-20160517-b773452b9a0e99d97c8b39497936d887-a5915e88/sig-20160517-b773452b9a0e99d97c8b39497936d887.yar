rule sig_20160517_b773452b9a0e99d97c8b39497936d887 {
  meta:
    description = "datamaliciousorder - file 20160517_b773452b9a0e99d97c8b39497936d887.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06a5dcff3d21321168b8951f2d62788396c97bad3bd9c068056b498a9d8b9fea"

  strings:
    $s1 = "var ua41='vm1smtaeyc44rwjjrz lrhesdavbjd1hzfpopknp14xfk3oofat2pkezlbit3wvoafmxafbu=njhmj\\'pzynntwthpicspx33ng2yfbidafmgfgkul2uq" ascii
    $s2 = "\"xp\");   pr2islia=r4+\"v\"+\"al\";   WScript.lister=5;   pr2islia=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}