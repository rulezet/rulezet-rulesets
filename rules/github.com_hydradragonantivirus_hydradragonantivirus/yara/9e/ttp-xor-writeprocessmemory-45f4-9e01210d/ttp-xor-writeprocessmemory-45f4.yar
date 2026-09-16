rule TTP_XOR_WriteProcessMemory_45f4 {
  strings:
    $key_45f4 = { 12 86 [2] 20 a4 [2] 26 91 [2] 08 91 [2] 37 8d }

  condition:
    any of them
}