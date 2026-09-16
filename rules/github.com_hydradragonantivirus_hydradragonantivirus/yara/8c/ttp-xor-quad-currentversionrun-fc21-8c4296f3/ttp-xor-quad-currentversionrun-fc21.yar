rule TTP_XOR_QUAD_CurrentVersionRun_fc21 {
  strings:
    $key_fc21 = { af 4e [2] 8b 40 [2] a0 6c [2] 8e 4e [2] 9a 55 [2] 95 4f [2] 8b 52 [2] 89 53 [2] 92 55 [2] 8e 52 [2] 92 7d }

  condition:
    any of them
}