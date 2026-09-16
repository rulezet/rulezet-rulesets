rule TTP_XOR_WriteProcessMemory_01f9 {
  strings:
    $key_01f9 = { 56 8b [2] 64 a9 [2] 62 9c [2] 4c 9c [2] 73 80 }

  condition:
    any of them
}