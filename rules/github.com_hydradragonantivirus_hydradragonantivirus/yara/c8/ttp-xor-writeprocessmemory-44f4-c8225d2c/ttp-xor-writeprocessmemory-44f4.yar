rule TTP_XOR_WriteProcessMemory_44f4 {
  strings:
    $key_44f4 = { 13 86 [2] 21 a4 [2] 27 91 [2] 09 91 [2] 36 8d }

  condition:
    any of them
}