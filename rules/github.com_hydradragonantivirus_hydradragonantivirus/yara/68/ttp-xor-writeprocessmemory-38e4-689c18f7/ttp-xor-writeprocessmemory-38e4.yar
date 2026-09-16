rule TTP_XOR_WriteProcessMemory_38e4 {
  strings:
    $key_38e4 = { 6f 96 [2] 5d b4 [2] 5b 81 [2] 75 81 [2] 4a 9d }

  condition:
    any of them
}