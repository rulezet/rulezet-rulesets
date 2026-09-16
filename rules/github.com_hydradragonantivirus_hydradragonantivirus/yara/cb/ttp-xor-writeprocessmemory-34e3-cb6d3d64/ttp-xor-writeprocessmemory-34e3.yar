rule TTP_XOR_WriteProcessMemory_34e3 {
  strings:
    $key_34e3 = { 63 91 [2] 51 b3 [2] 57 86 [2] 79 86 [2] 46 9a }

  condition:
    any of them
}