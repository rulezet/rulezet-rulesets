rule TTP_XOR_QUAD_CurrentVersionRun_1700 {
  strings:
    $key_1700 = { 44 6f [2] 60 61 [2] 4b 4d [2] 65 6f [2] 71 74 [2] 7e 6e [2] 60 73 [2] 62 72 [2] 79 74 [2] 65 73 [2] 79 5c }

  condition:
    any of them
}