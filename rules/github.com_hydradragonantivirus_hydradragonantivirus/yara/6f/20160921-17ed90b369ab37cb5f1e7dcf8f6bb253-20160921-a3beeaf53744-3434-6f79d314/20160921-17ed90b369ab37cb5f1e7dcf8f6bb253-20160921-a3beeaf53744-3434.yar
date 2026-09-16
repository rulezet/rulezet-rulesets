rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_a3beeaf53744_3434 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash3       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash4       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash5       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"
    hash6       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\";})(),(function f000(" ascii
    $s2 = "){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s3 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZIi\";})(),(funct" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Wb\";})(),(func" ascii
    $s5 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx" ascii
    $s6 = "rn \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}