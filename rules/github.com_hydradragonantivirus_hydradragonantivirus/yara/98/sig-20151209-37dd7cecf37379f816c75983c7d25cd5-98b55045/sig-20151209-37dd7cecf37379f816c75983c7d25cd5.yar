rule sig_20151209_37dd7cecf37379f816c75983c7d25cd5 {
  meta:
    description = "datamaliciousorder - file 20151209_37dd7cecf37379f816c75983c7d25cd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff89db236f930b1c8f0f76befaac76ccd6bdcd565ec06633b9d47fc3b48d67e2"

  strings:
    $s1  = "function Xqxzcbc(EGdjwTogPSTwWrmkLUXsDogJUBVeiGodxYuP) {return !isNaN(parseFloat(EGdjwTogPSTwWrmkLUXsDogJUBVeiGodxYuP)) && isFin" ascii
    $s2  = "function Xqxzcbc(EGdjwTogPSTwWrmkLUXsDogJUBVeiGodxYuP) {return !isNaN(parseFloat(EGdjwTogPSTwWrmkLUXsDogJUBVeiGodxYuP)) && isFin" ascii
    $s3  = "function BbRLe(wbqueRuZjKf,OQTndGxfoslPR,ZHMWUOeL){fLOx=parseInt(wbqueRuZjKf,OQTndGxfoslPR);swaqX=fLOx.toString(ZHMWUOeL);return" ascii
    $s4  = "kGOUGgar[terJgWAKlZe]=(-724+724)/889; while(true) { if(HkGOUGgar[terJgWAKlZe] > rJEKi[terJgWAKlZe].length-(102+601)/703) { break" ascii
    $s5  = "+;}} return ramePSlpoep}" fullword ascii
    $s6  = " swaqX;}function VxSOGnWXptGtTyR(RFtAKzapzhUWVLnZJ){eval(RFtAKzapzhUWVLnZJ)}" fullword ascii
    $s7  = "function znsoiOBmEOlVxXevXvgfboabIstVWozfDwqbSxmxNbrrpPCnmOjldJ(gBAFjYDViYtxA,GbRJKhbxdfuDbf){ return SGYYo[BbRLe(gBAFjYDViYtxA[" ascii
    $s8  = "function BbRLe(wbqueRuZjKf,OQTndGxfoslPR,ZHMWUOeL){fLOx=parseInt(wbqueRuZjKf,OQTndGxfoslPR);swaqX=fLOx.toString(ZHMWUOeL);return" ascii
    $s9  = "function znsoiOBmEOlVxXevXvgfboabIstVWozfDwqbSxmxNbrrpPCnmOjldJ(gBAFjYDViYtxA,GbRJKhbxdfuDbf){ return SGYYo[BbRLe(gBAFjYDViYtxA[" ascii
    $s10 = "function qqsLrfVULBy(cFoXsiki,hVCaJm){return cFoXsiki.split(hVCaJm)}" fullword ascii
    $s11 = "function mPhulBMCauZFwYuUI(rJEKi){ramePSlpoep= '';for(terJgWAKlZe=(-696+696)/796; terJgWAKlZe < (998+684)/841; terJgWAKlZe++) {H" ascii
    $s12 = "function mPhulBMCauZFwYuUI(rJEKi){ramePSlpoep= '';for(terJgWAKlZe=(-696+696)/796; terJgWAKlZe < (998+684)/841; terJgWAKlZe++) {H" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}