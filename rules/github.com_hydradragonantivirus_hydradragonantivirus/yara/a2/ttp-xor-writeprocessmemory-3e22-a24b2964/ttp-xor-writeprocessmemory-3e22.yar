rule TTP_XOR_WriteProcessMemory_3e22 {
  strings:
    $key_3e22 = { 69 50 [2] 5b 72 [2] 5d 47 [2] 73 47 [2] 4c 5b }

  condition:
    any of them
}