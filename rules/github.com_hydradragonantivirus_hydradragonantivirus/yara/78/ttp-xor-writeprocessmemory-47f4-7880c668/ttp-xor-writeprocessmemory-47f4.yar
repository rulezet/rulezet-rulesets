rule TTP_XOR_WriteProcessMemory_47f4 {
  strings:
    $key_47f4 = { 10 86 [2] 22 a4 [2] 24 91 [2] 0a 91 [2] 35 8d }

  condition:
    any of them
}