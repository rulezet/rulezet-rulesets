rule TTP_XOR_WriteProcessMemory_02e3 {
  strings:
    $key_02e3 = { 55 91 [2] 67 b3 [2] 61 86 [2] 4f 86 [2] 70 9a }

  condition:
    any of them
}