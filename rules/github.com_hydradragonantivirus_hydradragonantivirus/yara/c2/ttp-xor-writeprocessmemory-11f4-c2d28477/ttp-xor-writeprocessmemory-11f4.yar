rule TTP_XOR_WriteProcessMemory_11f4 {
  strings:
    $key_11f4 = { 46 86 [2] 74 a4 [2] 72 91 [2] 5c 91 [2] 63 8d }

  condition:
    any of them
}