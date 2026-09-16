rule TTP_XOR_QUAD_CurrentVersionRun_ec7b {
  strings:
    $key_ec7b = { bf 14 [2] 9b 1a [2] b0 36 [2] 9e 14 [2] 8a 0f [2] 85 15 [2] 9b 08 [2] 99 09 [2] 82 0f [2] 9e 08 [2] 82 27 }

  condition:
    any of them
}