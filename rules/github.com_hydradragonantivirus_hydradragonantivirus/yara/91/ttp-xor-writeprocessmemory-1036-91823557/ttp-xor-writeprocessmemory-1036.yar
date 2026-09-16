rule TTP_XOR_WriteProcessMemory_1036 {
  strings:
    $key_1036 = { 47 44 [2] 75 66 [2] 73 53 [2] 5d 53 [2] 62 4f }

  condition:
    any of them
}