rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_4758 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash3       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"

  strings:
    $s1 = "Gn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function" ascii
    $s2 = "unction f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii
    $s3 = ";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s4 = "ion f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s5 = "(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}