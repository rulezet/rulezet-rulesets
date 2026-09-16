rule TTP_XOR_QUAD_CurrentVersionRun_0e20 {
  strings:
    $key_0e20 = { 5d 4f [2] 79 41 [2] 52 6d [2] 7c 4f [2] 68 54 [2] 67 4e [2] 79 53 [2] 7b 52 [2] 60 54 [2] 7c 53 [2] 60 7c }

  condition:
    any of them
}