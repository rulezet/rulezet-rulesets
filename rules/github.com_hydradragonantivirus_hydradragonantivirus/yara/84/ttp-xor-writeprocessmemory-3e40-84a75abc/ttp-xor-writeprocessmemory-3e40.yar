rule TTP_XOR_WriteProcessMemory_3e40 {
  strings:
    $key_3e40 = { 69 32 [2] 5b 10 [2] 5d 25 [2] 73 25 [2] 4c 39 }

  condition:
    any of them
}