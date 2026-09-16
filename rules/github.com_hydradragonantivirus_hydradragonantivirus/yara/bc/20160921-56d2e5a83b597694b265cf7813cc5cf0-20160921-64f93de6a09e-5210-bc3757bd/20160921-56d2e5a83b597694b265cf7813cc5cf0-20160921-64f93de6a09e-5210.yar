rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_64f93de6a09e_5210 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js, 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash3       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash4       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash5       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash6       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"
    hash7       = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"
    hash8       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s2 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s4 = "n \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s5 = "turn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}