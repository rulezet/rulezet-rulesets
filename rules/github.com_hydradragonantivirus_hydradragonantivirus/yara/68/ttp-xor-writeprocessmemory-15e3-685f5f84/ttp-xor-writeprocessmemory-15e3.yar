rule TTP_XOR_WriteProcessMemory_15e3 {
  strings:
    $key_15e3 = { 42 91 [2] 70 b3 [2] 76 86 [2] 58 86 [2] 67 9a }

  condition:
    any of them
}