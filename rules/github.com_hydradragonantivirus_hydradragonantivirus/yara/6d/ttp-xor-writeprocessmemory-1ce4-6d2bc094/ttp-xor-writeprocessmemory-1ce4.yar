rule TTP_XOR_WriteProcessMemory_1ce4 {
  strings:
    $key_1ce4 = { 4b 96 [2] 79 b4 [2] 7f 81 [2] 51 81 [2] 6e 9d }

  condition:
    any of them
}