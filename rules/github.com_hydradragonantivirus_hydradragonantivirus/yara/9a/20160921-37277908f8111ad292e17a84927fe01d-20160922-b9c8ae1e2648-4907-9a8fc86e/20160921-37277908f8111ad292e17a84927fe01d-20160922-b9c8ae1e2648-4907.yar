rule _20160921_37277908f8111ad292e17a84927fe01d_20160922_b9c8ae1e2648_4907 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function" ascii
    $s2 = "f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\"" ascii
    $s3 = "urn \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(f" ascii
    $s4 = "{return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})" ascii
    $s5 = ";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}