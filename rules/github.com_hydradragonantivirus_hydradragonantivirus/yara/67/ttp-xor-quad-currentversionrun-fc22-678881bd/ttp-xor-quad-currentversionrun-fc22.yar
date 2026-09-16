rule TTP_XOR_QUAD_CurrentVersionRun_fc22 {
  strings:
    $key_fc22 = { af 4d [2] 8b 43 [2] a0 6f [2] 8e 4d [2] 9a 56 [2] 95 4c [2] 8b 51 [2] 89 50 [2] 92 56 [2] 8e 51 [2] 92 7e }

  condition:
    any of them
}