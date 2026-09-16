rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_527d7c375697_4985 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_527d7c3756974f804734da343b6b6f0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"

  strings:
    $s1 = ";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f0" ascii
    $s2 = "eturn \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})()," ascii
    $s3 = "c\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function " ascii
    $s4 = "(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Qa\";})(),(function f000(" ascii
    $s5 = "(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Ml\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}