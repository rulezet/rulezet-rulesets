rule TTP_XOR_WriteProcessMemory_678b {
  strings:
    $key_678b = { 30 f9 [2] 02 db [2] 04 ee [2] 2a ee [2] 15 f2 }

  condition:
    any of them
}