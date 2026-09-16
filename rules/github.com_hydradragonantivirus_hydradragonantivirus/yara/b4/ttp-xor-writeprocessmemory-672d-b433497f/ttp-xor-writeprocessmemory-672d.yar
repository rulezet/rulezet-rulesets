rule TTP_XOR_WriteProcessMemory_672d {
  strings:
    $key_672d = { 30 5f [2] 02 7d [2] 04 48 [2] 2a 48 [2] 15 54 }

  condition:
    any of them
}