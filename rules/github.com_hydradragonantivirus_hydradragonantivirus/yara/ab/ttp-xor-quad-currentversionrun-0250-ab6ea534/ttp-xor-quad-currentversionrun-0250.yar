rule TTP_XOR_QUAD_CurrentVersionRun_0250 {
  strings:
    $key_0250 = { 51 3f [2] 75 31 [2] 5e 1d [2] 70 3f [2] 64 24 [2] 6b 3e [2] 75 23 [2] 77 22 [2] 6c 24 [2] 70 23 [2] 6c 0c }

  condition:
    any of them
}