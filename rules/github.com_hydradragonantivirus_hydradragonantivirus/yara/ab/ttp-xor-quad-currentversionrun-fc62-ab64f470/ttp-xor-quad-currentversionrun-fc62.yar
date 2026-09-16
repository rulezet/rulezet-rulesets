rule TTP_XOR_QUAD_CurrentVersionRun_fc62 {
  strings:
    $key_fc62 = { af 0d [2] 8b 03 [2] a0 2f [2] 8e 0d [2] 9a 16 [2] 95 0c [2] 8b 11 [2] 89 10 [2] 92 16 [2] 8e 11 [2] 92 3e }

  condition:
    any of them
}