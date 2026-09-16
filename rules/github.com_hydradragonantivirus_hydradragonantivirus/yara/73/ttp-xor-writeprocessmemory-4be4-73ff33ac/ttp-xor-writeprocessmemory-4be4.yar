rule TTP_XOR_WriteProcessMemory_4be4 {
  strings:
    $key_4be4 = { 1c 96 [2] 2e b4 [2] 28 81 [2] 06 81 [2] 39 9d }

  condition:
    any of them
}