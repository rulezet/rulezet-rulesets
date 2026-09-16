rule TTP_XOR_WriteProcessMemory_6bf6 {
  strings:
    $key_6bf6 = { 3c 84 [2] 0e a6 [2] 08 93 [2] 26 93 [2] 19 8f }

  condition:
    any of them
}