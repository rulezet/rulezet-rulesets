rule TTP_XOR_WriteProcessMemory_6836 {
  strings:
    $key_6836 = { 3f 44 [2] 0d 66 [2] 0b 53 [2] 25 53 [2] 1a 4f }

  condition:
    any of them
}