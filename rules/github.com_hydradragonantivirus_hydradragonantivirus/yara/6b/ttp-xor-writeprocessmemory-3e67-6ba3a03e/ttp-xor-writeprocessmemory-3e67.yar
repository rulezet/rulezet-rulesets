rule TTP_XOR_WriteProcessMemory_3e67 {
  strings:
    $key_3e67 = { 69 15 [2] 5b 37 [2] 5d 02 [2] 73 02 [2] 4c 1e }

  condition:
    any of them
}