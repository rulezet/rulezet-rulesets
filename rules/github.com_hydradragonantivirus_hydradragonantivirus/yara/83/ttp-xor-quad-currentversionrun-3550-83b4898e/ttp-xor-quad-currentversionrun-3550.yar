rule TTP_XOR_QUAD_CurrentVersionRun_3550 {
  strings:
    $key_3550 = { 66 3f [2] 42 31 [2] 69 1d [2] 47 3f [2] 53 24 [2] 5c 3e [2] 42 23 [2] 40 22 [2] 5b 24 [2] 47 23 [2] 5b 0c }

  condition:
    any of them
}