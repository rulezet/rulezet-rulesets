rule TTP_XOR_WriteProcessMemory_4504 {
  strings:
    $key_4504 = { 12 76 [2] 20 54 [2] 26 61 [2] 08 61 [2] 37 7d }

  condition:
    any of them
}