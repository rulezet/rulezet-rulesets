rule TTP_XOR_WriteProcessMemory_28f4 {
  strings:
    $key_28f4 = { 7f 86 [2] 4d a4 [2] 4b 91 [2] 65 91 [2] 5a 8d }

  condition:
    any of them
}