rule TTP_XOR_QUAD_CurrentVersionRun_fc33 {
  strings:
    $key_fc33 = { af 5c [2] 8b 52 [2] a0 7e [2] 8e 5c [2] 9a 47 [2] 95 5d [2] 8b 40 [2] 89 41 [2] 92 47 [2] 8e 40 [2] 92 6f }

  condition:
    any of them
}