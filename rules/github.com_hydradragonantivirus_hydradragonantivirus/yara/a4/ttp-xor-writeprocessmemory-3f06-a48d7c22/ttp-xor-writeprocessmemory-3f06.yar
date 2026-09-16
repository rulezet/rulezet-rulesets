rule TTP_XOR_WriteProcessMemory_3f06 {
  strings:
    $key_3f06 = { 68 74 [2] 5a 56 [2] 5c 63 [2] 72 63 [2] 4d 7f }

  condition:
    any of them
}