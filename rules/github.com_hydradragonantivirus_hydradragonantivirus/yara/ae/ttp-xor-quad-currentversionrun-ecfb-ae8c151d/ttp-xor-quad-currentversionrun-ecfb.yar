rule TTP_XOR_QUAD_CurrentVersionRun_ecfb {
  strings:
    $key_ecfb = { bf 94 [2] 9b 9a [2] b0 b6 [2] 9e 94 [2] 8a 8f [2] 85 95 [2] 9b 88 [2] 99 89 [2] 82 8f [2] 9e 88 [2] 82 a7 }

  condition:
    any of them
}