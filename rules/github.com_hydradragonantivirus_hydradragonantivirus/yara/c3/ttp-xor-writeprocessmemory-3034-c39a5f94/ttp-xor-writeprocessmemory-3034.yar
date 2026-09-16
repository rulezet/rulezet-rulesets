rule TTP_XOR_WriteProcessMemory_3034 {
  strings:
    $key_3034 = { 67 46 [2] 55 64 [2] 53 51 [2] 7d 51 [2] 42 4d }

  condition:
    any of them
}