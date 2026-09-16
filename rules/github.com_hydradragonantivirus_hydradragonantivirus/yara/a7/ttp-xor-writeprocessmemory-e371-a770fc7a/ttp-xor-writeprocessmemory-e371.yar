rule TTP_XOR_WriteProcessMemory_e371 {
  strings:
    $key_e371 = { b4 03 [2] 86 21 [2] 80 14 [2] ae 14 [2] 91 08 }

  condition:
    any of them
}