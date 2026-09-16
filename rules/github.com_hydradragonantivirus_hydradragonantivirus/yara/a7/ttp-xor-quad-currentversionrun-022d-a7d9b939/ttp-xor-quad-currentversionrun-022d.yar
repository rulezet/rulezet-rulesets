rule TTP_XOR_QUAD_CurrentVersionRun_022d {
  strings:
    $key_022d = { 51 42 [2] 75 4c [2] 5e 60 [2] 70 42 [2] 64 59 [2] 6b 43 [2] 75 5e [2] 77 5f [2] 6c 59 [2] 70 5e [2] 6c 71 }

  condition:
    any of them
}