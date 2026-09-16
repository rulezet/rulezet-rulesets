rule TTP_XOR_WriteProcessMemory_672f {
  strings:
    $key_672f = { 30 5d [2] 02 7f [2] 04 4a [2] 2a 4a [2] 15 56 }

  condition:
    any of them
}