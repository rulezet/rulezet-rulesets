rule TTP_XOR_QUAD_CurrentVersionRun_e82c {
  strings:
    $key_e82c = { bb 43 [2] 9f 4d [2] b4 61 [2] 9a 43 [2] 8e 58 [2] 81 42 [2] 9f 5f [2] 9d 5e [2] 86 58 [2] 9a 5f [2] 86 70 }

  condition:
    any of them
}