rule TTP_XOR_QUAD_CurrentVersionRun_2b1d {
  strings:
    $key_2b1d = { 78 72 [2] 5c 7c [2] 77 50 [2] 59 72 [2] 4d 69 [2] 42 73 [2] 5c 6e [2] 5e 6f [2] 45 69 [2] 59 6e [2] 45 41 }

  condition:
    any of them
}