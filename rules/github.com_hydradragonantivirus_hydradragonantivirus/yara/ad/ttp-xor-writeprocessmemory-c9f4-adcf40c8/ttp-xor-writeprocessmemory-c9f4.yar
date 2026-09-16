rule TTP_XOR_WriteProcessMemory_c9f4 {
  strings:
    $key_c9f4 = { 9e 86 [2] ac a4 [2] aa 91 [2] 84 91 [2] bb 8d }

  condition:
    any of them
}