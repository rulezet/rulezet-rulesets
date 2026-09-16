rule TTP_XOR_QUAD_CurrentVersionRun_3ecc {
  strings:
    $key_3ecc = { 6d a3 [2] 49 ad [2] 62 81 [2] 4c a3 [2] 58 b8 [2] 57 a2 [2] 49 bf [2] 4b be [2] 50 b8 [2] 4c bf [2] 50 90 }

  condition:
    any of them
}