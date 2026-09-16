rule TTP_XOR_QUAD_CurrentVersionRun_6ccc {
  strings:
    $key_6ccc = { 3f a3 [2] 1b ad [2] 30 81 [2] 1e a3 [2] 0a b8 [2] 05 a2 [2] 1b bf [2] 19 be [2] 02 b8 [2] 1e bf [2] 02 90 }

  condition:
    any of them
}