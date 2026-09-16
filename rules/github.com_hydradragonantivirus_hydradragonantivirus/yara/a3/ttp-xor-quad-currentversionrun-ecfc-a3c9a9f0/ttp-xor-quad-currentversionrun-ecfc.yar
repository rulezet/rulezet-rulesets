rule TTP_XOR_QUAD_CurrentVersionRun_ecfc {
  strings:
    $key_ecfc = { bf 93 [2] 9b 9d [2] b0 b1 [2] 9e 93 [2] 8a 88 [2] 85 92 [2] 9b 8f [2] 99 8e [2] 82 88 [2] 9e 8f [2] 82 a0 }

  condition:
    any of them
}