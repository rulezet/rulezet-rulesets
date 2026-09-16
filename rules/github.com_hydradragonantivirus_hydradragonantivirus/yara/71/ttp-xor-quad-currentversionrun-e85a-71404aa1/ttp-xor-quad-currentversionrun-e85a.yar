rule TTP_XOR_QUAD_CurrentVersionRun_e85a {
  strings:
    $key_e85a = { bb 35 [2] 9f 3b [2] b4 17 [2] 9a 35 [2] 8e 2e [2] 81 34 [2] 9f 29 [2] 9d 28 [2] 86 2e [2] 9a 29 [2] 86 06 }

  condition:
    any of them
}