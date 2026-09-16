rule TTP_XOR_WriteProcessMemory_3be4 {
  strings:
    $key_3be4 = { 6c 96 [2] 5e b4 [2] 58 81 [2] 76 81 [2] 49 9d }

  condition:
    any of them
}