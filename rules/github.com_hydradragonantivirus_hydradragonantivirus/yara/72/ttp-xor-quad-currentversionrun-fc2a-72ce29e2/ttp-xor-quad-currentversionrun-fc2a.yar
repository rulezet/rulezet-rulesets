rule TTP_XOR_QUAD_CurrentVersionRun_fc2a {
  strings:
    $key_fc2a = { af 45 [2] 8b 4b [2] a0 67 [2] 8e 45 [2] 9a 5e [2] 95 44 [2] 8b 59 [2] 89 58 [2] 92 5e [2] 8e 59 [2] 92 76 }

  condition:
    any of them
}