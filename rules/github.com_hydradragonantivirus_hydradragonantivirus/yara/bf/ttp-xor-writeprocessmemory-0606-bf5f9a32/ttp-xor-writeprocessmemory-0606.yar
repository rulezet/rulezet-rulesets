rule TTP_XOR_WriteProcessMemory_0606 {
  strings:
    $key_0606 = { 51 74 [2] 63 56 [2] 65 63 [2] 4b 63 [2] 74 7f }

  condition:
    any of them
}