rule TTP_XOR_QUAD_CurrentVersionRun_7ecc {
  strings:
    $key_7ecc = { 2d a3 [2] 09 ad [2] 22 81 [2] 0c a3 [2] 18 b8 [2] 17 a2 [2] 09 bf [2] 0b be [2] 10 b8 [2] 0c bf [2] 10 90 }

  condition:
    any of them
}