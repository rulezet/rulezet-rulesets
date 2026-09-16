rule sig_20151216_488cae5d9543c8f6a6a32045f5f56230 {
  meta:
    description = "datamaliciousorder - file 20151216_488cae5d9543c8f6a6a32045f5f56230.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0a3117632c2e577d03bfdd3dcba0bb3fba37bd2ffbc43f33297a39a3d5c6fcf"

  strings:
    $s1  = ") - 1));while(true){if (qvTMUwskcXt >= (-378+708)/55){break;}jHjsdYPyz[qvTMUwskcXt]=Math.round((Math.pow(Math.sin(505), 2) + Mat" ascii
    $s2  = "h.pow(Math.cos(505), 2) - 1)); while(true) { if(jHjsdYPyz[qvTMUwskcXt] > UiNiq[qvTMUwskcXt].length-(159+337)/496) { break; } if " ascii
    $s3  = "w(Math.cos(412), 2) - 1)));} jHjsdYPyz[qvTMUwskcXt]++;}qvTMUwskcXt++;} return bjsbAhBCjQh}" fullword ascii
    $s4  = "function JKkmDeNaitqgnQlKK(UiNiq){bjsbAhBCjQh= '';qvTMUwskcXt=Math.round((Math.pow(Math.sin(499), 2) + Math.pow(Math.cos(499), 2" ascii
    $s5  = "function JKkmDeNaitqgnQlKK(UiNiq){bjsbAhBCjQh= '';qvTMUwskcXt=Math.round((Math.pow(Math.sin(499), 2) + Math.pow(Math.cos(499), 2" ascii
    $s6  = "function uTamYClHcYe(GLrmUSpnvUZKHt) {return isNaN(GLrmUSpnvUZKHt);}" fullword ascii
    $s7  = "function L(KJmsfUCHXeTCBH,iJLgJrZdgSbYF,jQFJIwdwFtY) {KJmsfUCHXeTCBH[iJLgJrZdgSbYF]=jQFJIwdwFtY;}" fullword ascii
    $s8  = "function ANEHYlrgihmHzkojYNGoehbbknqmVhMDAOiHfWYaMzflQbtEhXwodt(XfKwyGFRBJhNR,AqUZOkaQXUtBdQ){ return QmOpoLK[JBkEzhHD[XxyXj(XfK" ascii
    $s9  = ",'d','V','m','m','J','^','Y','W','z','Q','Q','5','!','X','X','f','J','Y','M','L','w','7','p','Z','[','$','f','g','H','z',String." ascii
    $s10 = "function ANEHYlrgihmHzkojYNGoehbbknqmVhMDAOiHfWYaMzflQbtEhXwodt(XfKwyGFRBJhNR,AqUZOkaQXUtBdQ){ return QmOpoLK[JBkEzhHD[XxyXj(XfK" ascii
    $s11 = "function igPotNhUTnXizHdyp(TqkJqmBQpO,tWmuvjOQOh) {return parseInt(TqkJqmBQpO,tWmuvjOQOh);}" fullword ascii
    $s12 = "function yXWkVACegzaqtkl(bXuHlVQXnDaIplpaQ,ivEFyfdHTswjrssjDPXOXfpeYPmhrivoCt,ZrAmsaillOsIDjkqUZgjqwDKWpGnZqIKwAS){eval(bXuHlVQX" ascii
    $s13 = "function yXWkVACegzaqtkl(bXuHlVQXnDaIplpaQ,ivEFyfdHTswjrssjDPXOXfpeYPmhrivoCt,ZrAmsaillOsIDjkqUZgjqwDKWpGnZqIKwAS){eval(bXuHlVQX" ascii
    $s14 = "function bectPmLrGfaK(VWCHoInHenuQR) {return isFinite(VWCHoInHenuQR);}" fullword ascii
    $s15 = "function D(WTEnHlOYGKab,yEIZimLchOPHYM){WTEnHlOYGKab.push(yEIZimLchOPHYM);}" fullword ascii
    $s16 = "B);return kfLmi;}" fullword ascii
    $s17 = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s18 = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s19 = "function uNWCnEC(QsEaHEdaswBEcOTTnHHGpOjMCZhHOnvZFBlv) {return !uTamYClHcYe(EhFTKchlCaHLUcn(QsEaHEdaswBEcOTTnHHGpOjMCZhHOnvZFBlv" ascii
    $s20 = "function XxyXj(yruRrAZGUNh,WzBItIpJXSDxN,nkZoTLRB){DQca=igPotNhUTnXizHdyp(yruRrAZGUNh,WzBItIpJXSDxN);kfLmi=DQca.toString(nkZoTLR" ascii

  condition:
    uint16(0) == 0x424a and
    8 of them
}