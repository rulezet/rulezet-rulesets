rule TTP_XOR_QUAD_CurrentVersionRun_ec51 {
  strings:
    $key_ec51 = { bf 3e [2] 9b 30 [2] b0 1c [2] 9e 3e [2] 8a 25 [2] 85 3f [2] 9b 22 [2] 99 23 [2] 82 25 [2] 9e 22 [2] 82 0d }

  condition:
    any of them
}