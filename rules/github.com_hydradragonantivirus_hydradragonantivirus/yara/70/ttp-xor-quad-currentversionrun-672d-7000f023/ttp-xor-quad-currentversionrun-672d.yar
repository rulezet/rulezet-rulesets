rule TTP_XOR_QUAD_CurrentVersionRun_672d {
  strings:
    $key_672d = { 34 42 [2] 10 4c [2] 3b 60 [2] 15 42 [2] 01 59 [2] 0e 43 [2] 10 5e [2] 12 5f [2] 09 59 [2] 15 5e [2] 09 71 }

  condition:
    any of them
}