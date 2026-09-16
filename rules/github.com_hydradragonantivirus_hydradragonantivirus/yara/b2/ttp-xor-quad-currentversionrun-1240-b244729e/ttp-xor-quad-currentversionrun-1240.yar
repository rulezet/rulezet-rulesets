rule TTP_XOR_QUAD_CurrentVersionRun_1240 {
  strings:
    $key_1240 = { 41 2f [2] 65 21 [2] 4e 0d [2] 60 2f [2] 74 34 [2] 7b 2e [2] 65 33 [2] 67 32 [2] 7c 34 [2] 60 33 [2] 7c 1c }

  condition:
    any of them
}