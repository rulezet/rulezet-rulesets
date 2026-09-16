rule TTP_XOR_QUAD_CurrentVersionRun_3c30 {
  strings:
    $key_3c30 = { 6f 5f [2] 4b 51 [2] 60 7d [2] 4e 5f [2] 5a 44 [2] 55 5e [2] 4b 43 [2] 49 42 [2] 52 44 [2] 4e 43 [2] 52 6c }

  condition:
    any of them
}