rule TTP_XOR_WriteProcessMemory_10f4 {
  strings:
    $key_10f4 = { 47 86 [2] 75 a4 [2] 73 91 [2] 5d 91 [2] 62 8d }

  condition:
    any of them
}