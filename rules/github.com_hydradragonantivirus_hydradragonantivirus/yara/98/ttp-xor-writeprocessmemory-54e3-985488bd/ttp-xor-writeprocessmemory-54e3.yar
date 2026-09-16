rule TTP_XOR_WriteProcessMemory_54e3 {
  strings:
    $key_54e3 = { 03 91 [2] 31 b3 [2] 37 86 [2] 19 86 [2] 26 9a }

  condition:
    any of them
}