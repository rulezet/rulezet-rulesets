rule TTP_XOR_WriteProcessMemory_248b {
  strings:
    $key_248b = { 73 f9 [2] 41 db [2] 47 ee [2] 69 ee [2] 56 f2 }

  condition:
    any of them
}