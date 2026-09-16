rule TTP_XOR_QUAD_CurrentVersionRun_2023 {
  strings:
    $key_2023 = { 73 4c [2] 57 42 [2] 7c 6e [2] 52 4c [2] 46 57 [2] 49 4d [2] 57 50 [2] 55 51 [2] 4e 57 [2] 52 50 [2] 4e 7f }

  condition:
    any of them
}