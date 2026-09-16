rule TTP_XOR_QUAD_CurrentVersionRun_ec7c {
  strings:
    $key_ec7c = { bf 13 [2] 9b 1d [2] b0 31 [2] 9e 13 [2] 8a 08 [2] 85 12 [2] 9b 0f [2] 99 0e [2] 82 08 [2] 9e 0f [2] 82 20 }

  condition:
    any of them
}