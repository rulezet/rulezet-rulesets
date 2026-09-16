rule TTP_XOR_QUAD_CurrentVersionRun_f1d1 {
  strings:
    $key_f1d1 = { a2 be [2] 86 b0 [2] ad 9c [2] 83 be [2] 97 a5 [2] 98 bf [2] 86 a2 [2] 84 a3 [2] 9f a5 [2] 83 a2 [2] 9f 8d }

  condition:
    any of them
}