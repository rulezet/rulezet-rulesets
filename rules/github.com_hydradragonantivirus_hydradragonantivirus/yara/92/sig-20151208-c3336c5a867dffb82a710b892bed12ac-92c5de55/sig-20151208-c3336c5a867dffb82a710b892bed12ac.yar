rule sig_20151208_c3336c5a867dffb82a710b892bed12ac {
  meta:
    description = "datamaliciousorder - file 20151208_c3336c5a867dffb82a710b892bed12ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec7f03d768291141c7de2e5d12f6dd646294e32c7b455582c8a7d88dbc89bbf8"

  strings:
    $s1  = "function hLioTqB(lmdLYFrayWJSkYgWlIlNFuKUVtrLJtSuukXw) {return !isNaN(parseFloat(lmdLYFrayWJSkYgWlIlNFuKUVtrLJtSuukXw)) && isFin" ascii
    $s2  = "function hLioTqB(lmdLYFrayWJSkYgWlIlNFuKUVtrLJtSuukXw) {return !isNaN(parseFloat(lmdLYFrayWJSkYgWlIlNFuKUVtrLJtSuukXw)) && isFin" ascii
    $s3  = "function NVGTDkEykxUcFYYWDTbOfAeWYjGzXNOLkDzLNiCmelGxVOhWMQNLZX(OoJAXsXpYkItT,CPpkpHpRgDHSDF){ return EJClQruwIDMup[feMry(OoJAXs" ascii
    $s4  = "function NVGTDkEykxUcFYYWDTbOfAeWYjGzXNOLkDzLNiCmelGxVOhWMQNLZX(OoJAXsXpYkItT,CPpkpHpRgDHSDF){ return EJClQruwIDMup[feMry(OoJAXs" ascii
    $s5  = "function WcRoCGgTvuOfuayjg(hADFl){OLtKHDLKeMW= '';for(jXCcjmLSAUw=(-298+298)/215; jXCcjmLSAUw < (-276+752)/238; jXCcjmLSAUw++) {" ascii
    $s6  = "push(\"43\");L.push(\"71\");L.push(\"91\");L.push(\"115\");L.push(\"93\");L.push(\"43\");L.push(\"72\");L.push(\"44\");L.push(\"" ascii
    $s7  = "push(\"32\");L.push(\"32\");L.push(\"125\");L.push(\"59\");L.push(\"32\");L.push(\"108\");L.push(\"82\");L.push(\"67\");L.push(" ascii
    $s8  = "push(\"108\");x.push(\"32\");x.push(\"43\");x.push(\"32\");x.push(\"34\");x.push(\"84\");x.push(\"84\");x.push(\"80\");x.push(\"" ascii
    $s9  = "push(\"55\");x.push(\"48\");x.push(\"48\");x.push(\"49\");x.push(\"55\");x.push(\"117\");x.push(\"77\");x.push(\"51\");x.push(\"" ascii
    $s10 = "push(\"32\");L.push(\"115\");L.push(\"61\");L.push(\"117\");L.push(\"72\");L.push(\"113\");L.push(\"59\");L.push(\"32\");L.push(" ascii
    $s11 = "function WcRoCGgTvuOfuayjg(hADFl){OLtKHDLKeMW= '';for(jXCcjmLSAUw=(-298+298)/215; jXCcjmLSAUw < (-276+752)/238; jXCcjmLSAUw++) {" ascii
    $s12 = "push(\"45\");x.push(\"105\");x.push(\"110\");x.push(\"99\");x.push(\"108\");x.push(\"117\");x.push(\"100\");x.push(\"101\");x.pu" ascii
    $s13 = "vmbPaduwP[jXCcjmLSAUw]=(-159+159)/447; while(true) { if(vmbPaduwP[jXCcjmLSAUw] > hADFl[jXCcjmLSAUw].length-(322+61)/383) { break" ascii
    $s14 = "function pktbgzWPslS(nHbZCnpF,gSsvaw){return nHbZCnpF.split(gSsvaw)}" fullword ascii
    $s15 = "push(\"32\");L.push(\"32\");L.push(\"32\");L.push(\"32\");L.push(\"32\");L.push(\"32\");L.push(\"32\");L.push(\"125\");L.push(\"" ascii
    $s16 = "push(\"97\");x.push(\"114\");x.push(\"32\");x.push(\"108\");x.push(\"114\");x.push(\"73\");x.push(\"32\");x.push(\"61\");x.push(" ascii
    $s17 = "+;}} return OLtKHDLKeMW}" fullword ascii
    $s18 = "push(\"105\");L.push(\"116\");L.push(\"101\");L.push(\"40\");L.push(\"119\");L.push(\"70\");L.push(\"46\");L.push(\"114\");L.pus" ascii
    $s19 = "push(\"9\");L.push(\"105\");L.push(\"102\");L.push(\"32\");L.push(\"40\");L.push(\"77\");L.push(\"110\");L.push(\"32\");L.push(" ascii
    $s20 = "push(\"82\");L.push(\"67\");L.push(\"46\");L.push(\"115\");L.push(\"97\");L.push(\"118\");L.push(\"101\");L.push(\"84\");L.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}