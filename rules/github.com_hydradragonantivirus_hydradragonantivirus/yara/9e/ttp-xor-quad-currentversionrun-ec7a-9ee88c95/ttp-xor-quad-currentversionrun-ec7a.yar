rule TTP_XOR_QUAD_CurrentVersionRun_ec7a {
  strings:
    $key_ec7a = { bf 15 [2] 9b 1b [2] b0 37 [2] 9e 15 [2] 8a 0e [2] 85 14 [2] 9b 09 [2] 99 08 [2] 82 0e [2] 9e 09 [2] 82 26 }

  condition:
    any of them
}