rule TTP_XOR_QUAD_CurrentVersionRun_2300 {
  strings:
    $key_2300 = { 70 6f [2] 54 61 [2] 7f 4d [2] 51 6f [2] 45 74 [2] 4a 6e [2] 54 73 [2] 56 72 [2] 4d 74 [2] 51 73 [2] 4d 5c }

  condition:
    any of them
}