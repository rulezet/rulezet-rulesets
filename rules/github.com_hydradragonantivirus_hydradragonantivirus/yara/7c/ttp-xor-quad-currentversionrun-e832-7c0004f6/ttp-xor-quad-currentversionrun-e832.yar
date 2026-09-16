rule TTP_XOR_QUAD_CurrentVersionRun_e832 {
  strings:
    $key_e832 = { bb 5d [2] 9f 53 [2] b4 7f [2] 9a 5d [2] 8e 46 [2] 81 5c [2] 9f 41 [2] 9d 40 [2] 86 46 [2] 9a 41 [2] 86 6e }

  condition:
    any of them
}