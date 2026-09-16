rule TTP_XOR_WriteProcessMemory_54f4 {
  strings:
    $key_54f4 = { 03 86 [2] 31 a4 [2] 37 91 [2] 19 91 [2] 26 8d }

  condition:
    any of them
}