rule TTP_XOR_WriteProcessMemory_e311 {
  strings:
    $key_e311 = { b4 63 [2] 86 41 [2] 80 74 [2] ae 74 [2] 91 68 }

  condition:
    any of them
}