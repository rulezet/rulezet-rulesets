rule TTP_XOR_WriteProcessMemory_3ef9 {
  strings:
    $key_3ef9 = { 69 8b [2] 5b a9 [2] 5d 9c [2] 73 9c [2] 4c 80 }

  condition:
    any of them
}