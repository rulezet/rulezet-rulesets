rule TTP_XOR_WriteProcessMemory_4134 {
  strings:
    $key_4134 = { 16 46 [2] 24 64 [2] 22 51 [2] 0c 51 [2] 33 4d }

  condition:
    any of them
}