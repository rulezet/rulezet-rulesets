rule TTP_XOR_WriteProcessMemory_6fe4 {
  strings:
    $key_6fe4 = { 38 96 [2] 0a b4 [2] 0c 81 [2] 22 81 [2] 1d 9d }

  condition:
    any of them
}