rule _20160921_64f93de6a09e8b98cdca7da04504cdef_20160921_a1d83c8f2541_2101 {
  meta:
    description = "datamaliciousorder - from files 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash2       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash3       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash4       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash5       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash6       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1 = "f000(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJ" ascii
    $s2 = "){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";}" ascii
    $s3 = "eturn \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";})()" ascii
    $s4 = ",(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s5 = "\"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(functi" ascii
    $s6 = "ction f000(){return \"Sq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return" ascii
    $s7 = "n \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s8 = "})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f00" ascii
    $s9 = "n f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}