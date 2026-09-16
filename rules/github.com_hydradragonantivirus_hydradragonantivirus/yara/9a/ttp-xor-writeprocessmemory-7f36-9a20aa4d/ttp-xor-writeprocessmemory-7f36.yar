rule TTP_XOR_WriteProcessMemory_7f36 {
  strings:
    $key_7f36 = { 28 44 [2] 1a 66 [2] 1c 53 [2] 32 53 [2] 0d 4f }

  condition:
    any of them
}