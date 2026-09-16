rule TTP_XOR_QUAD_CurrentVersionRun_fc1b {
  strings:
    $key_fc1b = { af 74 [2] 8b 7a [2] a0 56 [2] 8e 74 [2] 9a 6f [2] 95 75 [2] 8b 68 [2] 89 69 [2] 92 6f [2] 8e 68 [2] 92 47 }

  condition:
    any of them
}