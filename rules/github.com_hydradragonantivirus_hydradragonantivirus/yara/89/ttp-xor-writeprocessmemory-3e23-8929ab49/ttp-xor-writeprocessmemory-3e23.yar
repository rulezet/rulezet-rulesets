rule TTP_XOR_WriteProcessMemory_3e23 {
  strings:
    $key_3e23 = { 69 51 [2] 5b 73 [2] 5d 46 [2] 73 46 [2] 4c 5a }

  condition:
    any of them
}