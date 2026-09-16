rule TTP_XOR_QUAD_CurrentVersionRun_e822 {
  strings:
    $key_e822 = { bb 4d [2] 9f 43 [2] b4 6f [2] 9a 4d [2] 8e 56 [2] 81 4c [2] 9f 51 [2] 9d 50 [2] 86 56 [2] 9a 51 [2] 86 7e }

  condition:
    any of them
}