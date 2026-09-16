rule TTP_XOR_QUAD_CurrentVersionRun_3300 {
  strings:
    $key_3300 = { 60 6f [2] 44 61 [2] 6f 4d [2] 41 6f [2] 55 74 [2] 5a 6e [2] 44 73 [2] 46 72 [2] 5d 74 [2] 41 73 [2] 5d 5c }

  condition:
    any of them
}