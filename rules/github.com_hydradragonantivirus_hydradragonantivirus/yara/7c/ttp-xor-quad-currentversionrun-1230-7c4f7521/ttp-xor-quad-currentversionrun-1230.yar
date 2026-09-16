rule TTP_XOR_QUAD_CurrentVersionRun_1230 {
  strings:
    $key_1230 = { 41 5f [2] 65 51 [2] 4e 7d [2] 60 5f [2] 74 44 [2] 7b 5e [2] 65 43 [2] 67 42 [2] 7c 44 [2] 60 43 [2] 7c 6c }

  condition:
    any of them
}