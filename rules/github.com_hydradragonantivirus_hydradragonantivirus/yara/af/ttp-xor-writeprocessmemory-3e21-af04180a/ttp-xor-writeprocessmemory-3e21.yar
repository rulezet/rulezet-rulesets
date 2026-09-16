rule TTP_XOR_WriteProcessMemory_3e21 {
  strings:
    $key_3e21 = { 69 53 [2] 5b 71 [2] 5d 44 [2] 73 44 [2] 4c 58 }

  condition:
    any of them
}