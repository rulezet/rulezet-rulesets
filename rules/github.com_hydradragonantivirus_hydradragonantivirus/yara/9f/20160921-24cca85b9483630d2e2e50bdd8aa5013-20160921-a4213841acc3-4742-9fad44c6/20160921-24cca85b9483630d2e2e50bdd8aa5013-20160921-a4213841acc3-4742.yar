rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_a4213841acc3_4742 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash3       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"

  strings:
    $s1 = "nction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s2 = "f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn" ascii
    $s3 = "})(),(function f000(){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f00" ascii
    $s4 = "(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000()" ascii
    $s5 = "0(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}