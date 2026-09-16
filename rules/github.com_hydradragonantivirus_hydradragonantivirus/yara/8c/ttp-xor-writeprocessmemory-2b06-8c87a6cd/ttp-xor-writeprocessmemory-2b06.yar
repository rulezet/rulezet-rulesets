rule TTP_XOR_WriteProcessMemory_2b06 {
  strings:
    $key_2b06 = { 7c 74 [2] 4e 56 [2] 48 63 [2] 66 63 [2] 59 7f }

  condition:
    any of them
}