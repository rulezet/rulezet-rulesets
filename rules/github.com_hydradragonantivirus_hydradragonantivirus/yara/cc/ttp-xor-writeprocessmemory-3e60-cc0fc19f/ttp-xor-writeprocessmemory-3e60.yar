rule TTP_XOR_WriteProcessMemory_3e60 {
  strings:
    $key_3e60 = { 69 12 [2] 5b 30 [2] 5d 05 [2] 73 05 [2] 4c 19 }

  condition:
    any of them
}