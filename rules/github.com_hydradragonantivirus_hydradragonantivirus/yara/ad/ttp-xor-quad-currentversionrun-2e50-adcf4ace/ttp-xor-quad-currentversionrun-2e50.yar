rule TTP_XOR_QUAD_CurrentVersionRun_2e50 {
  strings:
    $key_2e50 = { 7d 3f [2] 59 31 [2] 72 1d [2] 5c 3f [2] 48 24 [2] 47 3e [2] 59 23 [2] 5b 22 [2] 40 24 [2] 5c 23 [2] 40 0c }

  condition:
    any of them
}