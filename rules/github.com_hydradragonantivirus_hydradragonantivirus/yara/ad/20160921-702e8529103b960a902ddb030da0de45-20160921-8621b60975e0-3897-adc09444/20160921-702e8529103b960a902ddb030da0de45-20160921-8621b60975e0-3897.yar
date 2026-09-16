rule _20160921_702e8529103b960a902ddb030da0de45_20160921_8621b60975e0_3897 {
  meta:
    description = "datamaliciousorder - from files 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_8843826fc0ae466921b7811b54d8314e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"

  strings:
    $s1 = "return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})()" ascii
    $s2 = "urn \"MBb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3 = "on f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s4 = " f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"M" ascii
    $s5 = "),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s6 = "(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}