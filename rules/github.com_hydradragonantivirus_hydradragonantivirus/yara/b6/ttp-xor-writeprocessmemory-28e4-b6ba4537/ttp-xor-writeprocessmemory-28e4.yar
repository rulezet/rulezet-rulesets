rule TTP_XOR_WriteProcessMemory_28e4 {
  strings:
    $key_28e4 = { 7f 96 [2] 4d b4 [2] 4b 81 [2] 65 81 [2] 5a 9d }

  condition:
    any of them
}