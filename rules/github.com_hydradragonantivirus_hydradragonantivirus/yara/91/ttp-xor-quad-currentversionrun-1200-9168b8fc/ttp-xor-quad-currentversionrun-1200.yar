rule TTP_XOR_QUAD_CurrentVersionRun_1200 {
  strings:
    $key_1200 = { 41 6f [2] 65 61 [2] 4e 4d [2] 60 6f [2] 74 74 [2] 7b 6e [2] 65 73 [2] 67 72 [2] 7c 74 [2] 60 73 [2] 7c 5c }

  condition:
    any of them
}