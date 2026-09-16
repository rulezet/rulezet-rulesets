rule TTP_XOR_QUAD_CurrentVersionRun_4741 {
  strings:
    $key_4741 = { 14 2e [2] 30 20 [2] 1b 0c [2] 35 2e [2] 21 35 [2] 2e 2f [2] 30 32 [2] 32 33 [2] 29 35 [2] 35 32 [2] 29 1d }

  condition:
    any of them
}