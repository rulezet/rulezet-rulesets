rule TTP_XOR_WriteProcessMemory_32ce {
  strings:
    $key_32ce = { 65 bc [2] 57 9e [2] 51 ab [2] 7f ab [2] 40 b7 }

  condition:
    any of them
}