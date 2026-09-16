rule TTP_XOR_WriteProcessMemory_3f65 {
  strings:
    $key_3f65 = { 68 17 [2] 5a 35 [2] 5c 00 [2] 72 00 [2] 4d 1c }

  condition:
    any of them
}