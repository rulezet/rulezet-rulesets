rule TTP_XOR_QUAD_CurrentVersionRun_ec62 {
  strings:
    $key_ec62 = { bf 0d [2] 9b 03 [2] b0 2f [2] 9e 0d [2] 8a 16 [2] 85 0c [2] 9b 11 [2] 99 10 [2] 82 16 [2] 9e 11 [2] 82 3e }

  condition:
    any of them
}