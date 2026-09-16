rule TTP_XOR_QUAD_CurrentVersionRun_ec4f {
  strings:
    $key_ec4f = { bf 20 [2] 9b 2e [2] b0 02 [2] 9e 20 [2] 8a 3b [2] 85 21 [2] 9b 3c [2] 99 3d [2] 82 3b [2] 9e 3c [2] 82 13 }

  condition:
    any of them
}