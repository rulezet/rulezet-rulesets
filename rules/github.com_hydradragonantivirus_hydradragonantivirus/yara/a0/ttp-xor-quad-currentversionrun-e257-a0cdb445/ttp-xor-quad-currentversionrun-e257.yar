rule TTP_XOR_QUAD_CurrentVersionRun_e257 {
  strings:
    $key_e257 = { b1 38 [2] 95 36 [2] be 1a [2] 90 38 [2] 84 23 [2] 8b 39 [2] 95 24 [2] 97 25 [2] 8c 23 [2] 90 24 [2] 8c 0b }

  condition:
    any of them
}