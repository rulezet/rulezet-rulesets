rule TTP_XOR_QUAD_CurrentVersionRun_2941 {
  strings:
    $key_2941 = { 7a 2e [2] 5e 20 [2] 75 0c [2] 5b 2e [2] 4f 35 [2] 40 2f [2] 5e 32 [2] 5c 33 [2] 47 35 [2] 5b 32 [2] 47 1d }

  condition:
    any of them
}