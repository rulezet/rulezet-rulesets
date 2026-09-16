rule TTP_XOR_QUAD_CurrentVersionRun_025d {
  strings:
    $key_025d = { 51 32 [2] 75 3c [2] 5e 10 [2] 70 32 [2] 64 29 [2] 6b 33 [2] 75 2e [2] 77 2f [2] 6c 29 [2] 70 2e [2] 6c 01 }

  condition:
    any of them
}