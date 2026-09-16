rule TTP_XOR_QUAD_CurrentVersionRun_672b {
  strings:
    $key_672b = { 34 44 [2] 10 4a [2] 3b 66 [2] 15 44 [2] 01 5f [2] 0e 45 [2] 10 58 [2] 12 59 [2] 09 5f [2] 15 58 [2] 09 77 }

  condition:
    any of them
}