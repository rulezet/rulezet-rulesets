rule TTP_XOR_WriteProcessMemory_21f4 {
  strings:
    $key_21f4 = { 76 86 [2] 44 a4 [2] 42 91 [2] 6c 91 [2] 53 8d }

  condition:
    any of them
}