rule TTP_XOR_QUAD_CurrentVersionRun_ec21 {
  strings:
    $key_ec21 = { bf 4e [2] 9b 40 [2] b0 6c [2] 9e 4e [2] 8a 55 [2] 85 4f [2] 9b 52 [2] 99 53 [2] 82 55 [2] 9e 52 [2] 82 7d }

  condition:
    any of them
}