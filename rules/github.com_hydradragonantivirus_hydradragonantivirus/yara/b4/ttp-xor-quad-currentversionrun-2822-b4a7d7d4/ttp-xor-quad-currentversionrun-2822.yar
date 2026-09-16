rule TTP_XOR_QUAD_CurrentVersionRun_2822 {
  strings:
    $key_2822 = { 7b 4d [2] 5f 43 [2] 74 6f [2] 5a 4d [2] 4e 56 [2] 41 4c [2] 5f 51 [2] 5d 50 [2] 46 56 [2] 5a 51 [2] 46 7e }

  condition:
    any of them
}