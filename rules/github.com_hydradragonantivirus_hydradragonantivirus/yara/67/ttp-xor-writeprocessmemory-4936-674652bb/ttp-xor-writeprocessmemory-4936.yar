rule TTP_XOR_WriteProcessMemory_4936 {
  strings:
    $key_4936 = { 1e 44 [2] 2c 66 [2] 2a 53 [2] 04 53 [2] 3b 4f }

  condition:
    any of them
}