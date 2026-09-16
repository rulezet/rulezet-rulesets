rule TTP_XOR_QUAD_CurrentVersionRun_fc1a {
  strings:
    $key_fc1a = { af 75 [2] 8b 7b [2] a0 57 [2] 8e 75 [2] 9a 6e [2] 95 74 [2] 8b 69 [2] 89 68 [2] 92 6e [2] 8e 69 [2] 92 46 }

  condition:
    any of them
}