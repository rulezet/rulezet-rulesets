rule TTP_XOR_QUAD_CurrentVersionRun_31e0 {
  strings:
    $key_31e0 = { 62 8f [2] 46 81 [2] 6d ad [2] 43 8f [2] 57 94 [2] 58 8e [2] 46 93 [2] 44 92 [2] 5f 94 [2] 43 93 [2] 5f bc }

  condition:
    any of them
}