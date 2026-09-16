rule TTP_XOR_WriteProcessMemory_c979 {
  strings:
    $key_c979 = { 9e 0b [2] ac 29 [2] aa 1c [2] 84 1c [2] bb 00 }

  condition:
    any of them
}