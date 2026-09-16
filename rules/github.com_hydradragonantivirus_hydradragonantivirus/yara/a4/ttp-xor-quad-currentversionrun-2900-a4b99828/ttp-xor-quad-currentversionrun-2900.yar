rule TTP_XOR_QUAD_CurrentVersionRun_2900 {
  strings:
    $key_2900 = { 7a 6f [2] 5e 61 [2] 75 4d [2] 5b 6f [2] 4f 74 [2] 40 6e [2] 5e 73 [2] 5c 72 [2] 47 74 [2] 5b 73 [2] 47 5c }

  condition:
    any of them
}