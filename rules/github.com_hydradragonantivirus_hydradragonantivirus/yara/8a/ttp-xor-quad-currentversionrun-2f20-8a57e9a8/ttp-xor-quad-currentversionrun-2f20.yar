rule TTP_XOR_QUAD_CurrentVersionRun_2f20 {
  strings:
    $key_2f20 = { 7c 4f [2] 58 41 [2] 73 6d [2] 5d 4f [2] 49 54 [2] 46 4e [2] 58 53 [2] 5a 52 [2] 41 54 [2] 5d 53 [2] 41 7c }

  condition:
    any of them
}