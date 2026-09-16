rule TTP_XOR_WriteProcessMemory_13e3 {
  strings:
    $key_13e3 = { 44 91 [2] 76 b3 [2] 70 86 [2] 5e 86 [2] 61 9a }

  condition:
    any of them
}