rule TTP_XOR_WriteProcessMemory_bfde {
  strings:
    $key_bfde = { e8 ac [2] da 8e [2] dc bb [2] f2 bb [2] cd a7 }

  condition:
    any of them
}