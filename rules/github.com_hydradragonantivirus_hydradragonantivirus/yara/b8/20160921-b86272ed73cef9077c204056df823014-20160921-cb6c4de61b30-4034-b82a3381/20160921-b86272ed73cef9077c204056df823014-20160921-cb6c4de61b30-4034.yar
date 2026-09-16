rule _20160921_b86272ed73cef9077c204056df823014_20160921_cb6c4de61b30_4034 {
  meta:
    description = "datamaliciousorder - from files 20160921_b86272ed73cef9077c204056df823014.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "rn \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s2 = "urn \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(fu" ascii
    $s3 = "n \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5 = "eturn \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})()," ascii
    $s6 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}