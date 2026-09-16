rule TTP_XOR_WriteProcessMemory_5be4 {
  strings:
    $key_5be4 = { 0c 96 [2] 3e b4 [2] 38 81 [2] 16 81 [2] 29 9d }

  condition:
    any of them
}