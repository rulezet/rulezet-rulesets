rule TTP_XOR_QUAD_CurrentVersionRun_2800 {
  strings:
    $key_2800 = { 7b 6f [2] 5f 61 [2] 74 4d [2] 5a 6f [2] 4e 74 [2] 41 6e [2] 5f 73 [2] 5d 72 [2] 46 74 [2] 5a 73 [2] 46 5c }

  condition:
    any of them
}