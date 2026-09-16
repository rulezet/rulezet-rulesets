rule TTP_XOR_QUAD_CurrentVersionRun_3041 {
  strings:
    $key_3041 = { 63 2e [2] 47 20 [2] 6c 0c [2] 42 2e [2] 56 35 [2] 59 2f [2] 47 32 [2] 45 33 [2] 5e 35 [2] 42 32 [2] 5e 1d }

  condition:
    any of them
}