rule _20160921_aaf08d1a708106f9bd09a913767a56e1_20160921_aed247f3d228_5623 {
  meta:
    description = "datamaliciousorder - from files 20160921_aaf08d1a708106f9bd09a913767a56e1.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"
    hash2       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash3       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash4       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"

  strings:
    $s1 = "\"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(funct" ascii
    $s2 = "){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){retu" ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){retur" ascii
    $s5 = "(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}