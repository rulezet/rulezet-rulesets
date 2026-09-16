rule TTP_XOR_QUAD_CurrentVersionRun_e83a {
  strings:
    $key_e83a = { bb 55 [2] 9f 5b [2] b4 77 [2] 9a 55 [2] 8e 4e [2] 81 54 [2] 9f 49 [2] 9d 48 [2] 86 4e [2] 9a 49 [2] 86 66 }

  condition:
    any of them
}