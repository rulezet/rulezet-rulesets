rule TTP_XOR_QUAD_CurrentVersionRun_f822 {
  strings:
    $key_f822 = { ab 4d [2] 8f 43 [2] a4 6f [2] 8a 4d [2] 9e 56 [2] 91 4c [2] 8f 51 [2] 8d 50 [2] 96 56 [2] 8a 51 [2] 96 7e }

  condition:
    any of them
}