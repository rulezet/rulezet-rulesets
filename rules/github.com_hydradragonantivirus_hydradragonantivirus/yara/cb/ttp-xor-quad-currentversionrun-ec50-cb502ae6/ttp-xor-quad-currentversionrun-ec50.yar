rule TTP_XOR_QUAD_CurrentVersionRun_ec50 {
  strings:
    $key_ec50 = { bf 3f [2] 9b 31 [2] b0 1d [2] 9e 3f [2] 8a 24 [2] 85 3e [2] 9b 23 [2] 99 22 [2] 82 24 [2] 9e 23 [2] 82 0c }

  condition:
    any of them
}