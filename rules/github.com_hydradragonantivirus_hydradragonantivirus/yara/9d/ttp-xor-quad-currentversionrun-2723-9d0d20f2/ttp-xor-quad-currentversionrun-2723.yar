rule TTP_XOR_QUAD_CurrentVersionRun_2723 {
  strings:
    $key_2723 = { 74 4c [2] 50 42 [2] 7b 6e [2] 55 4c [2] 41 57 [2] 4e 4d [2] 50 50 [2] 52 51 [2] 49 57 [2] 55 50 [2] 49 7f }

  condition:
    any of them
}