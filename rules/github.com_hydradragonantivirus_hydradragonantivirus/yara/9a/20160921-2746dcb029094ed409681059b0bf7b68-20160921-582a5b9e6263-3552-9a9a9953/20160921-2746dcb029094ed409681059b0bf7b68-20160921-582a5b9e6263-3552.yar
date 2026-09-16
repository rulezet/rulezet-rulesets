rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_3552 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash3       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1 = "0(){return \"Ot\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";" ascii
    $s2 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii
    $s3 = "f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KX" ascii
    $s4 = ",(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000()" ascii
    $s5 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(f" ascii
    $s6 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}