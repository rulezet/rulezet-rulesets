rule TTP_XOR_QUAD_CurrentVersionRun_3050 {
  strings:
    $key_3050 = { 63 3f [2] 47 31 [2] 6c 1d [2] 42 3f [2] 56 24 [2] 59 3e [2] 47 23 [2] 45 22 [2] 5e 24 [2] 42 23 [2] 5e 0c }

  condition:
    any of them
}