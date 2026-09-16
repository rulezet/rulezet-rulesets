rule TTP_XOR_QUAD_CurrentVersionRun_fc1d {
  strings:
    $key_fc1d = { af 72 [2] 8b 7c [2] a0 50 [2] 8e 72 [2] 9a 69 [2] 95 73 [2] 8b 6e [2] 89 6f [2] 92 69 [2] 8e 6e [2] 92 41 }

  condition:
    any of them
}