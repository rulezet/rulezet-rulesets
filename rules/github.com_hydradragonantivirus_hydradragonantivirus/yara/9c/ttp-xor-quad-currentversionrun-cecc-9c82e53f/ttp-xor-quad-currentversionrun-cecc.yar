rule TTP_XOR_QUAD_CurrentVersionRun_cecc {
  strings:
    $key_cecc = { 9d a3 [2] b9 ad [2] 92 81 [2] bc a3 [2] a8 b8 [2] a7 a2 [2] b9 bf [2] bb be [2] a0 b8 [2] bc bf [2] a0 90 }

  condition:
    any of them
}