rule TTP_XOR_QUAD_CurrentVersionRun_6ecc {
  strings:
    $key_6ecc = { 3d a3 [2] 19 ad [2] 32 81 [2] 1c a3 [2] 08 b8 [2] 07 a2 [2] 19 bf [2] 1b be [2] 00 b8 [2] 1c bf [2] 00 90 }

  condition:
    any of them
}