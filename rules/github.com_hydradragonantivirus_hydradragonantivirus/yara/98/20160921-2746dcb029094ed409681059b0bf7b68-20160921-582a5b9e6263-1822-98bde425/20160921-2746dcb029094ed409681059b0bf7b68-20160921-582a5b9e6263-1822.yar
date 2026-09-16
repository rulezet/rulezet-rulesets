rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_1822 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash3       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1  = "){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";}" ascii
    $s2  = "return \"SEo\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(" ascii
    $s3  = "tion f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return " ascii
    $s4  = "n f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s5  = "nction f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){retu" ascii
    $s6  = "{return \"SGs\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s7  = " \"RVb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(func" ascii
    $s8  = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s9  = "ction f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s10 = "nction f000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}