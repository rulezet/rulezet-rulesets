rule TTP_XOR_QUAD_CurrentVersionRun_f831 {
  strings:
    $key_f831 = { ab 5e [2] 8f 50 [2] a4 7c [2] 8a 5e [2] 9e 45 [2] 91 5f [2] 8f 42 [2] 8d 43 [2] 96 45 [2] 8a 42 [2] 96 6d }

  condition:
    any of them
}