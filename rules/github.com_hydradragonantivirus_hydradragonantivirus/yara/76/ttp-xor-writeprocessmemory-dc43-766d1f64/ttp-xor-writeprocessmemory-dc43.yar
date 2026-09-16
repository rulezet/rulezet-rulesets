rule TTP_XOR_WriteProcessMemory_dc43 {
  strings:
    $key_dc43 = { 8b 31 [2] b9 13 [2] bf 26 [2] 91 26 [2] ae 3a }

  condition:
    any of them
}