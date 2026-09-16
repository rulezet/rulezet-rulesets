rule TTP_XOR_WriteProcessMemory_3437 {
  strings:
    $key_3437 = { 63 45 [2] 51 67 [2] 57 52 [2] 79 52 [2] 46 4e }

  condition:
    any of them
}