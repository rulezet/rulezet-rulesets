rule TTP_XOR_QUAD_CurrentVersionRun_ec3f {
  strings:
    $key_ec3f = { bf 50 [2] 9b 5e [2] b0 72 [2] 9e 50 [2] 8a 4b [2] 85 51 [2] 9b 4c [2] 99 4d [2] 82 4b [2] 9e 4c [2] 82 63 }

  condition:
    any of them
}