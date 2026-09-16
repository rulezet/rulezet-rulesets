rule TTP_XOR_WriteProcessMemory_218b {
  strings:
    $key_218b = { 76 f9 [2] 44 db [2] 42 ee [2] 6c ee [2] 53 f2 }

  condition:
    any of them
}