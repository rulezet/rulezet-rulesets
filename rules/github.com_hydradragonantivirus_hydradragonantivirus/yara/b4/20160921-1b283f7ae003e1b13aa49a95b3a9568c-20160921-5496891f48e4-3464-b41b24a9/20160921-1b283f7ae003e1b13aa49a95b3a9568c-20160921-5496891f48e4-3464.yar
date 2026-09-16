rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_5496891f48e4_3464 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"

  strings:
    $s1 = " f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Z" ascii
    $s2 = "eturn \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})()" ascii
    $s3 = "{return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})" ascii
    $s4 = "){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";}" ascii
    $s5 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";" ascii
    $s6 = "ion f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}