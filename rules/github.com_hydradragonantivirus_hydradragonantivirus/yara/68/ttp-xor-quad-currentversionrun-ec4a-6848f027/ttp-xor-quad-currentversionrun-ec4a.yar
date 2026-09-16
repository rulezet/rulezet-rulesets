rule TTP_XOR_QUAD_CurrentVersionRun_ec4a {
  strings:
    $key_ec4a = { bf 25 [2] 9b 2b [2] b0 07 [2] 9e 25 [2] 8a 3e [2] 85 24 [2] 9b 39 [2] 99 38 [2] 82 3e [2] 9e 39 [2] 82 16 }

  condition:
    any of them
}