rule TTP_XOR_WriteProcessMemory_2f36 {
  strings:
    $key_2f36 = { 78 44 [2] 4a 66 [2] 4c 53 [2] 62 53 [2] 5d 4f }

  condition:
    any of them
}