rule TTP_XOR_QUAD_CurrentVersionRun_1ccc {
  strings:
    $key_1ccc = { 4f a3 [2] 6b ad [2] 40 81 [2] 6e a3 [2] 7a b8 [2] 75 a2 [2] 6b bf [2] 69 be [2] 72 b8 [2] 6e bf [2] 72 90 }

  condition:
    any of them
}