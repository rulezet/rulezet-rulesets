rule sig_20151217_3b053e6f2033020fb4e372d0b239081c {
  meta:
    description = "datamaliciousorder - file 20151217_3b053e6f2033020fb4e372d0b239081c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163a5ecec8fde33876fb8a1737f2705b6cfe80953fe427976b147d33988b430d"

  strings:
    $s1  = "function uBGtWnvkJORMEQzqs(NjehN){FUKlSFbhcVH= '';RHQYOmjXeYY=Math.round((Math.pow(Math.sin(953), 2) + Math.pow(Math.cos(953), 2" ascii
    $s2  = ".pow(Math.cos(785), 2) - 1)));} piZQrkFyi[RHQYOmjXeYY]++;}RHQYOmjXeYY++;} return FUKlSFbhcVH}" fullword ascii
    $s3  = "th.pow(Math.cos(104), 2) - 1)); while(true) { if(piZQrkFyi[RHQYOmjXeYY] > NjehN[RHQYOmjXeYY].length-(-119+338)/219) { break; } i" ascii
    $s4  = ") - 1));while(true){if (RHQYOmjXeYY >= (4142+598)/790){break;}piZQrkFyi[RHQYOmjXeYY]=Math.round((Math.pow(Math.sin(104), 2) + Ma" ascii
    $s5  = "FesYMPWzjRbWQXsIvnlxFsHjJOOyJUtygExX([NjehN[RHQYOmjXeYY][piZQrkFyi[RHQYOmjXeYY]]], Math.round((Math.pow(Math.sin(785), 2) + Math" ascii
    $s6  = "function uBGtWnvkJORMEQzqs(NjehN){FUKlSFbhcVH= '';RHQYOmjXeYY=Math.round((Math.pow(Math.sin(953), 2) + Math.pow(Math.cos(953), 2" ascii
    $s7  = "function NBdzJZEfFwGIyRi(GFBbkSfBjSAMDJhuP,OxjZHwTVpXpOcCwPhsZFhovNlRdAndFHUF,BHNpcjzRRCsKXicVkOmbkJCNcJYRcfAlBJD){eval(GFBbkSfB" ascii
    $s8  = "function NBdzJZEfFwGIyRi(GFBbkSfBjSAMDJhuP,OxjZHwTVpXpOcCwPhsZFhovNlRdAndFHUF,BHNpcjzRRCsKXicVkOmbkJCNcJYRcfAlBJD){eval(GFBbkSfB" ascii
    $s9  = "function ZQTGXlw(JHadyfEiebijfIUGHPhttoKyxWPeoyqqMwoP) {return !CUMFYXZBThb(uxnPYCHAvzVqErK(JHadyfEiebijfIUGHPhttoKyxWPeoyqqMwoP" ascii
    $s10 = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s11 = "function uxnPYCHAvzVqErK(IeuGnQOoZHBVkVAxVbF) {return parseFloat(IeuGnQOoZHBVkVAxVbF);}" fullword ascii
    $s12 = "function LQRPg(ouFsudoylAY,LPtVnOZOPYfFR,XMtvvTvW){BshQ=HbnzvdQkEFgyGSaOD(ouFsudoylAY,LPtVnOZOPYfFR);ErUIu=BshQ.toString(XMtvvTv" ascii
    $s13 = ",',','_','V','p','^','W','c',' ','t','0','X','C','0','m','q','Y','s','T','C','Z','a','h','O','v','L','[','[','^','P','_',String." ascii
    $s14 = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s15 = "function LQRPg(ouFsudoylAY,LPtVnOZOPYfFR,XMtvvTvW){BshQ=HbnzvdQkEFgyGSaOD(ouFsudoylAY,LPtVnOZOPYfFR);ErUIu=BshQ.toString(XMtvvTv" ascii
    $s16 = "function U(kQnFUsIPqfUw,KmxNdfukLbcBhr){kQnFUsIPqfUw.push(KmxNdfukLbcBhr);}" fullword ascii
    $s17 = "function HbnzvdQkEFgyGSaOD(aQHVihzcPt,bTbHzjftHl) {return parseInt(aQHVihzcPt,bTbHzjftHl);}" fullword ascii
    $s18 = "function ZQTGXlw(JHadyfEiebijfIUGHPhttoKyxWPeoyqqMwoP) {return !CUMFYXZBThb(uxnPYCHAvzVqErK(JHadyfEiebijfIUGHPhttoKyxWPeoyqqMwoP" ascii
    $s19 = "W);return ErUIu;}" fullword ascii
    $s20 = "function zmFyCHXkCvKK(uWAUCJjVeLKGH) {return isFinite(uWAUCJjVeLKGH);}" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}