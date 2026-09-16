rule TTP_XOR_QUAD_CurrentVersionRun_e237 {
  strings:
    $key_e237 = { b1 58 [2] 95 56 [2] be 7a [2] 90 58 [2] 84 43 [2] 8b 59 [2] 95 44 [2] 97 45 [2] 8c 43 [2] 90 44 [2] 8c 6b }

  condition:
    any of them
}