rule TTP_XOR_WriteProcessMemory_0be4 {
  strings:
    $key_0be4 = { 5c 96 [2] 6e b4 [2] 68 81 [2] 46 81 [2] 79 9d }

  condition:
    any of them
}