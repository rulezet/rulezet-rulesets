rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_4c22609fd731_4717 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_e1835bc92c4604db194bc49df621cade.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash3       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash4       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash5       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = "{return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000" ascii
    $s3 = "urn \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(fu" ascii
    $s4 = "unction f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){ret" ascii
    $s5 = "000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}