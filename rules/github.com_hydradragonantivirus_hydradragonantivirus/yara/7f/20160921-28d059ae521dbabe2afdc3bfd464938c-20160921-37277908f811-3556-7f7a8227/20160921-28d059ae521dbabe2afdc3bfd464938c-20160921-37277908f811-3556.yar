rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_37277908f811_3556 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_37277908f8111ad292e17a84927fe01d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"

  strings:
    $s1 = "rn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s2 = "unction f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = "unction f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s4 = " \"MMz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s5 = "){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})" ascii
    $s6 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}