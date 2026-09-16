rule TTP_XOR_QUAD_CurrentVersionRun_5822 {
  strings:
    $key_5822 = { 0b 4d [2] 2f 43 [2] 04 6f [2] 2a 4d [2] 3e 56 [2] 31 4c [2] 2f 51 [2] 2d 50 [2] 36 56 [2] 2a 51 [2] 36 7e }

  condition:
    any of them
}