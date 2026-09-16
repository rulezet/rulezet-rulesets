rule TTP_XOR_QUAD_CurrentVersionRun_2700 {
  strings:
    $key_2700 = { 74 6f [2] 50 61 [2] 7b 4d [2] 55 6f [2] 41 74 [2] 4e 6e [2] 50 73 [2] 52 72 [2] 49 74 [2] 55 73 [2] 49 5c }

  condition:
    any of them
}