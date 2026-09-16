rule TTP_XOR_WriteProcessMemory_3836 {
  strings:
    $key_3836 = { 6f 44 [2] 5d 66 [2] 5b 53 [2] 75 53 [2] 4a 4f }

  condition:
    any of them
}