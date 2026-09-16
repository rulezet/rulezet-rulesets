rule _20160921_aed247f3d2282ef44bd04021d1a47ef8_20160921_b9bf4d000983_3119 {
  meta:
    description = "datamaliciousorder - from files 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash2       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash3       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1 = "{return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})" ascii
    $s2 = "PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s3 = "eturn \"MJq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})()," ascii
    $s4 = "){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})" ascii
    $s5 = "),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){" ascii
    $s6 = "Yh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function" ascii
    $s7 = " f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}