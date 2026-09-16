rule TTP_XOR_WriteProcessMemory_bf27 {
  strings:
    $key_bf27 = { e8 55 [2] da 77 [2] dc 42 [2] f2 42 [2] cd 5e }

  condition:
    any of them
}