rule TTP_XOR_QUAD_CurrentVersionRun_ec6d {
  strings:
    $key_ec6d = { bf 02 [2] 9b 0c [2] b0 20 [2] 9e 02 [2] 8a 19 [2] 85 03 [2] 9b 1e [2] 99 1f [2] 82 19 [2] 9e 1e [2] 82 31 }

  condition:
    any of them
}