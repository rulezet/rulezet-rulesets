rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_f3a36d70a836_4174 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "urn \"SGs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s2 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(fu" ascii
    $s3 = "on f000(){return \"MJq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "unction f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s5 = "n f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}