rule TTP_XOR_WriteProcessMemory_78f4 {
  strings:
    $key_78f4 = { 2f 86 [2] 1d a4 [2] 1b 91 [2] 35 91 [2] 0a 8d }

  condition:
    any of them
}