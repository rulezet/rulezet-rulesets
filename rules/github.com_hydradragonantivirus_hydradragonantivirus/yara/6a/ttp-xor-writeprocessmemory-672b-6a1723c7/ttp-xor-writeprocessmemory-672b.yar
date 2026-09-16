rule TTP_XOR_WriteProcessMemory_672b {
  strings:
    $key_672b = { 30 59 [2] 02 7b [2] 04 4e [2] 2a 4e [2] 15 52 }

  condition:
    any of them
}