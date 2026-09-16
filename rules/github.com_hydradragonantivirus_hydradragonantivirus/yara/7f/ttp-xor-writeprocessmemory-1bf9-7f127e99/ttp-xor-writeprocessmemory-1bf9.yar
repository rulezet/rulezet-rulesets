rule TTP_XOR_WriteProcessMemory_1bf9 {
  strings:
    $key_1bf9 = { 4c 8b [2] 7e a9 [2] 78 9c [2] 56 9c [2] 69 80 }

  condition:
    any of them
}