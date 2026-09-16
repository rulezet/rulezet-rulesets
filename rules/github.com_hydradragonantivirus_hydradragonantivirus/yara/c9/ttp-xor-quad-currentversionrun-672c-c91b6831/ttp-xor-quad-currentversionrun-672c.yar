rule TTP_XOR_QUAD_CurrentVersionRun_672c {
  strings:
    $key_672c = { 34 43 [2] 10 4d [2] 3b 61 [2] 15 43 [2] 01 58 [2] 0e 42 [2] 10 5f [2] 12 5e [2] 09 58 [2] 15 5f [2] 09 70 }

  condition:
    any of them
}