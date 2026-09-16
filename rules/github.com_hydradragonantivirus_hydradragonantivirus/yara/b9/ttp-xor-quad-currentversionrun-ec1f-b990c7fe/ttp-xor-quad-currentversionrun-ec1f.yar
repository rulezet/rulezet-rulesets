rule TTP_XOR_QUAD_CurrentVersionRun_ec1f {
  strings:
    $key_ec1f = { bf 70 [2] 9b 7e [2] b0 52 [2] 9e 70 [2] 8a 6b [2] 85 71 [2] 9b 6c [2] 99 6d [2] 82 6b [2] 9e 6c [2] 82 43 }

  condition:
    any of them
}