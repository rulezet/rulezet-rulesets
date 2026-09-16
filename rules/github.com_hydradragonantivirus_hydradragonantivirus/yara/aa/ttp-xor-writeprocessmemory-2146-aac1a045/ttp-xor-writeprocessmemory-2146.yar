rule TTP_XOR_WriteProcessMemory_2146 {
  strings:
    $key_2146 = { 76 34 [2] 44 16 [2] 42 23 [2] 6c 23 [2] 53 3f }

  condition:
    any of them
}