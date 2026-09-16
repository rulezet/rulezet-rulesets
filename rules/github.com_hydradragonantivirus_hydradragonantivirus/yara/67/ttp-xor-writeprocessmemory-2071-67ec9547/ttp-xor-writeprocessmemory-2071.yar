rule TTP_XOR_WriteProcessMemory_2071 {
  strings:
    $key_2071 = { 77 03 [2] 45 21 [2] 43 14 [2] 6d 14 [2] 52 08 }

  condition:
    any of them
}