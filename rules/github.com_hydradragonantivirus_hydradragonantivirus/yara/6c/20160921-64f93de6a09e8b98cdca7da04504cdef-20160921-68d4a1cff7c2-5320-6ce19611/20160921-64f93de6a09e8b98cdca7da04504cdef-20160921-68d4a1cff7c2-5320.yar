rule _20160921_64f93de6a09e8b98cdca7da04504cdef_20160921_68d4a1cff7c2_5320 {
  meta:
    description = "datamaliciousorder - from files 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash2       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash3       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash4       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash5       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1 = " f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s2 = "urn \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s3 = "n f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s4 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KDh\";})(),(" ascii
    $s5 = "rn \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}