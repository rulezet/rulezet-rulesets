rule TTP_XOR_QUAD_CurrentVersionRun_ec7d {
  strings:
    $key_ec7d = { bf 12 [2] 9b 1c [2] b0 30 [2] 9e 12 [2] 8a 09 [2] 85 13 [2] 9b 0e [2] 99 0f [2] 82 09 [2] 9e 0e [2] 82 21 }

  condition:
    any of them
}