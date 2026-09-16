rule TTP_XOR_WriteProcessMemory_66f4 {
  strings:
    $key_66f4 = { 31 86 [2] 03 a4 [2] 05 91 [2] 2b 91 [2] 14 8d }

  condition:
    any of them
}