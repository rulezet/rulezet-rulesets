rule TTP_XOR_QUAD_CurrentVersionRun_e2e4 {
  strings:
    $key_e2e4 = { b1 8b [2] 95 85 [2] be a9 [2] 90 8b [2] 84 90 [2] 8b 8a [2] 95 97 [2] 97 96 [2] 8c 90 [2] 90 97 [2] 8c b8 }

  condition:
    any of them
}