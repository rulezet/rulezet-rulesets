rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_8843826fc0ae_4769 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_8843826fc0ae466921b7811b54d8314e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"

  strings:
    $s1 = "nction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s2 = "unction f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){ret" ascii
    $s3 = "(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TRc\";}" ascii
    $s4 = "ction f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){retur" ascii
    $s5 = "z\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NYh\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}