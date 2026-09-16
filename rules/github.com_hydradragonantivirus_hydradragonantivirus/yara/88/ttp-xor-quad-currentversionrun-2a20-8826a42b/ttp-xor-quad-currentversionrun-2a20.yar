rule TTP_XOR_QUAD_CurrentVersionRun_2a20 {
  strings:
    $key_2a20 = { 79 4f [2] 5d 41 [2] 76 6d [2] 58 4f [2] 4c 54 [2] 43 4e [2] 5d 53 [2] 5f 52 [2] 44 54 [2] 58 53 [2] 44 7c }

  condition:
    any of them
}