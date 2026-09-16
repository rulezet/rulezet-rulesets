rule TTP_XOR_WriteProcessMemory_55e3 {
  strings:
    $key_55e3 = { 02 91 [2] 30 b3 [2] 36 86 [2] 18 86 [2] 27 9a }

  condition:
    any of them
}