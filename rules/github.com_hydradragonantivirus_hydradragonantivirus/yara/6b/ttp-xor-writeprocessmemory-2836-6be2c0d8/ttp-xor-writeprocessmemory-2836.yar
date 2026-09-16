rule TTP_XOR_WriteProcessMemory_2836 {
  strings:
    $key_2836 = { 7f 44 [2] 4d 66 [2] 4b 53 [2] 65 53 [2] 5a 4f }

  condition:
    any of them
}