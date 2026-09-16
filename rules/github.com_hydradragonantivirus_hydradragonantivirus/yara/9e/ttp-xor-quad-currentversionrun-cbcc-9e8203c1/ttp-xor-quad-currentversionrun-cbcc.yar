rule TTP_XOR_QUAD_CurrentVersionRun_cbcc {
  strings:
    $key_cbcc = { 98 a3 [2] bc ad [2] 97 81 [2] b9 a3 [2] ad b8 [2] a2 a2 [2] bc bf [2] be be [2] a5 b8 [2] b9 bf [2] a5 90 }

  condition:
    any of them
}