rule sig_20151216_170ed0f10778628cbfd072113fc413a1 {
  meta:
    description = "datamaliciousorder - file 20151216_170ed0f10778628cbfd072113fc413a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93cf5d06c7f22d6083cbdbfd472861efe0c6a8147ddc24773ddae837d4a16e82"

  strings:
    $s1  = "ow(Math.cos(242), 2) - 1)));} mhpYsQSOL[CZRRPNpAbwm]++;}CZRRPNpAbwm++;} return UXoRoWKdKRT}" fullword ascii
    $s2  = "th.pow(Math.cos(420), 2) - 1)); while(true) { if(mhpYsQSOL[CZRRPNpAbwm] > AhOxk[CZRRPNpAbwm].length-(-852+983)/131) { break; } i" ascii
    $s3  = "function zJSnNIUDhxXUIkIbp(AhOxk){UXoRoWKdKRT= '';CZRRPNpAbwm=Math.round((Math.pow(Math.sin(797), 2) + Math.pow(Math.cos(797), 2" ascii
    $s4  = ") - 1));while(true){if (CZRRPNpAbwm >= (1924+842)/461){break;}mhpYsQSOL[CZRRPNpAbwm]=Math.round((Math.pow(Math.sin(420), 2) + Ma" ascii
    $s5  = "function zJSnNIUDhxXUIkIbp(AhOxk){UXoRoWKdKRT= '';CZRRPNpAbwm=Math.round((Math.pow(Math.sin(797), 2) + Math.pow(Math.cos(797), 2" ascii
    $s6  = "function IjvhIJs(uVqEaFYjtbInYpiYSbPmuxqAlpyjQHXuyOgQ) {return !HrodVjFQiII(BYgCiJahWMrHKOJ(uVqEaFYjtbInYpiYSbPmuxqAlpyjQHXuyOgQ" ascii
    $s7  = "function IjvhIJs(uVqEaFYjtbInYpiYSbPmuxqAlpyjQHXuyOgQ) {return !HrodVjFQiII(BYgCiJahWMrHKOJ(uVqEaFYjtbInYpiYSbPmuxqAlpyjQHXuyOgQ" ascii
    $s8  = "function Q(mfVpBRorqWMkAg,clIZlZXoImmLh,VNaXYxptWra) {mfVpBRorqWMkAg[clIZlZXoImmLh]=VNaXYxptWra;}" fullword ascii
    $s9  = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s10 = "function RuQljpKglprhqun(yOMCxpYnUfKoTqWYS,eBCdTyNFSZKEWKRnAlbraUvFxDFkTJdjVV,wbhrBlzuhrqgmItntfPxkxGEQmMSoSZaAHd){eval(yOMCxpYn" ascii
    $s11 = "function RuQljpKglprhqun(yOMCxpYnUfKoTqWYS,eBCdTyNFSZKEWKRnAlbraUvFxDFkTJdjVV,wbhrBlzuhrqgmItntfPxkxGEQmMSoSZaAHd){eval(yOMCxpYn" ascii
    $s12 = "function B(wQYmTrIIjCDY,JMMaRnYYyUljBz){wQYmTrIIjCDY.push(JMMaRnYYyUljBz);}" fullword ascii
    $s13 = "function bAUaQzfzFKzchstQqhJfEQkbCDRgeqeeYofLlIKkgpOEdwFRREHbvX(pSVQwaqUZFmXK,GKwbMtLAaXzuOq){ return zeHpFRq[IIEaygRB[bXyso(pSV" ascii
    $s14 = "function bXyso(LttUdGHGKRh,eMdffJNXjezOP,hHuiYhUN){ClWV=zToqgfmefjdnLmzHo(LttUdGHGKRh,eMdffJNXjezOP);vzIIn=ClWV.toString(hHuiYhU" ascii
    $s15 = "function HrodVjFQiII(IqmeTizzmmvZcP) {return isNaN(IqmeTizzmmvZcP);}" fullword ascii
    $s16 = "function bAUaQzfzFKzchstQqhJfEQkbCDRgeqeeYofLlIKkgpOEdwFRREHbvX(pSVQwaqUZFmXK,GKwbMtLAaXzuOq){ return zeHpFRq[IIEaygRB[bXyso(pSV" ascii
    $s17 = "N);return vzIIn;}" fullword ascii
    $s18 = "function bXyso(LttUdGHGKRh,eMdffJNXjezOP,hHuiYhUN){ClWV=zToqgfmefjdnLmzHo(LttUdGHGKRh,eMdffJNXjezOP);vzIIn=ClWV.toString(hHuiYhU" ascii
    $s19 = "function zToqgfmefjdnLmzHo(whidOSPEyo,atubNypOMs) {return parseInt(whidOSPEyo,atubNypOMs);}" fullword ascii
    $s20 = "function BYgCiJahWMrHKOJ(BzSYudXbgQRolNpwFxO) {return parseFloat(BzSYudXbgQRolNpwFxO);}" fullword ascii

  condition:
    uint16(0) == 0x4949 and
    8 of them
}