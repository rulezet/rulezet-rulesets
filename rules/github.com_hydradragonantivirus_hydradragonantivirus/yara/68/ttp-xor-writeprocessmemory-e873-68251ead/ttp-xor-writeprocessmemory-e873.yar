rule TTP_XOR_WriteProcessMemory_e873 {
  strings:
    $key_e873 = { bf 01 [2] 8d 23 [2] 8b 16 [2] a5 16 [2] 9a 0a }

  condition:
    any of them
}