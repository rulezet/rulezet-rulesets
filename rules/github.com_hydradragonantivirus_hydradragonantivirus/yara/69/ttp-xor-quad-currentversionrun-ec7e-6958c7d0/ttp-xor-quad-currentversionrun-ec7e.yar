rule TTP_XOR_QUAD_CurrentVersionRun_ec7e {
  strings:
    $key_ec7e = { bf 11 [2] 9b 1f [2] b0 33 [2] 9e 11 [2] 8a 0a [2] 85 10 [2] 9b 0d [2] 99 0c [2] 82 0a [2] 9e 0d [2] 82 22 }

  condition:
    any of them
}