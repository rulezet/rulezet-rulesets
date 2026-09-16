rule TTP_XOR_QUAD_CurrentVersionRun_e820 {
  strings:
    $key_e820 = { bb 4f [2] 9f 41 [2] b4 6d [2] 9a 4f [2] 8e 54 [2] 81 4e [2] 9f 53 [2] 9d 52 [2] 86 54 [2] 9a 53 [2] 86 7c }

  condition:
    any of them
}