rule TTP_XOR_QUAD_CurrentVersionRun_3c50 {
  strings:
    $key_3c50 = { 6f 3f [2] 4b 31 [2] 60 1d [2] 4e 3f [2] 5a 24 [2] 55 3e [2] 4b 23 [2] 49 22 [2] 52 24 [2] 4e 23 [2] 52 0c }

  condition:
    any of them
}