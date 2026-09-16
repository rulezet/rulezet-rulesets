rule TTP_XOR_WriteProcessMemory_52e4 {
  strings:
    $key_52e4 = { 05 96 [2] 37 b4 [2] 31 81 [2] 1f 81 [2] 20 9d }

  condition:
    any of them
}