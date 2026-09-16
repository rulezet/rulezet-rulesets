rule TTP_XOR_WriteProcessMemory_3f23 {
  strings:
    $key_3f23 = { 68 51 [2] 5a 73 [2] 5c 46 [2] 72 46 [2] 4d 5a }

  condition:
    any of them
}