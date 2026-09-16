rule _20160921_9ed8ba5d12b4be06b54bbeb7c9325180_20160921_be9238446370_5596 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash2       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash3       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "on f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s2 = "(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3 = "000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq" ascii
    $s4 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DNa\";})()," ascii
    $s5 = "rn \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}