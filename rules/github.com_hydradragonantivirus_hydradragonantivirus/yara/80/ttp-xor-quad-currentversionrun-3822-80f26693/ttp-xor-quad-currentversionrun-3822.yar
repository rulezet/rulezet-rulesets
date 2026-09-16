rule TTP_XOR_QUAD_CurrentVersionRun_3822 {
  strings:
    $key_3822 = { 6b 4d [2] 4f 43 [2] 64 6f [2] 4a 4d [2] 5e 56 [2] 51 4c [2] 4f 51 [2] 4d 50 [2] 56 56 [2] 4a 51 [2] 56 7e }

  condition:
    any of them
}