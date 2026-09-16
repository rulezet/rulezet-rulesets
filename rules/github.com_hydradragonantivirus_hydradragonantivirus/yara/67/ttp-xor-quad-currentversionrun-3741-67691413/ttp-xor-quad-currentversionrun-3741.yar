rule TTP_XOR_QUAD_CurrentVersionRun_3741 {
  strings:
    $key_3741 = { 64 2e [2] 40 20 [2] 6b 0c [2] 45 2e [2] 51 35 [2] 5e 2f [2] 40 32 [2] 42 33 [2] 59 35 [2] 45 32 [2] 59 1d }

  condition:
    any of them
}