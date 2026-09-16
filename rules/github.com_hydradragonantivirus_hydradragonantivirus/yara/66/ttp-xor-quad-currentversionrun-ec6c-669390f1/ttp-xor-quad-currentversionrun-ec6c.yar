rule TTP_XOR_QUAD_CurrentVersionRun_ec6c {
  strings:
    $key_ec6c = { bf 03 [2] 9b 0d [2] b0 21 [2] 9e 03 [2] 8a 18 [2] 85 02 [2] 9b 1f [2] 99 1e [2] 82 18 [2] 9e 1f [2] 82 30 }

  condition:
    any of them
}