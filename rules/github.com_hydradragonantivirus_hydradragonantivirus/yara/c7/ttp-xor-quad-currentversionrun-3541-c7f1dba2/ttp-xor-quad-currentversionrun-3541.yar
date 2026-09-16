rule TTP_XOR_QUAD_CurrentVersionRun_3541 {
  strings:
    $key_3541 = { 66 2e [2] 42 20 [2] 69 0c [2] 47 2e [2] 53 35 [2] 5c 2f [2] 42 32 [2] 40 33 [2] 5b 35 [2] 47 32 [2] 5b 1d }

  condition:
    any of them
}