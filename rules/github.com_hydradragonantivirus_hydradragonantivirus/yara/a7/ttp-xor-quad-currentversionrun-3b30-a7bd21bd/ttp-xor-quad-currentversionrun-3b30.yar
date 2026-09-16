rule TTP_XOR_QUAD_CurrentVersionRun_3b30 {
  strings:
    $key_3b30 = { 68 5f [2] 4c 51 [2] 67 7d [2] 49 5f [2] 5d 44 [2] 52 5e [2] 4c 43 [2] 4e 42 [2] 55 44 [2] 49 43 [2] 55 6c }

  condition:
    any of them
}