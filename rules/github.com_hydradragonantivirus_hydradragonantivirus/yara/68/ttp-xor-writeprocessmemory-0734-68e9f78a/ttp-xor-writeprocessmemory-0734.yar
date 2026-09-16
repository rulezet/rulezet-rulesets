rule TTP_XOR_WriteProcessMemory_0734 {
  strings:
    $key_0734 = { 50 46 [2] 62 64 [2] 64 51 [2] 4a 51 [2] 75 4d }

  condition:
    any of them
}