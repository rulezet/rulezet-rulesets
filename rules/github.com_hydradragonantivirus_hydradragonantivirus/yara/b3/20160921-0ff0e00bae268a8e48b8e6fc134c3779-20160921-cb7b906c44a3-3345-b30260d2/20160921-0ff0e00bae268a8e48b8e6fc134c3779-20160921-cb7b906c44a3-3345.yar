rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_cb7b906c44a3_3345 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1 = "(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";}" ascii
    $s2 = "0(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";}" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f000(){retu" ascii
    $s4 = "ction f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retur" ascii
    $s5 = "),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){" ascii
    $s6 = "return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}