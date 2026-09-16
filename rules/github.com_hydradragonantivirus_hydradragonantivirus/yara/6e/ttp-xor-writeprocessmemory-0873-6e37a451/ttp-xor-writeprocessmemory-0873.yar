rule TTP_XOR_WriteProcessMemory_0873 {
  strings:
    $key_0873 = { 5f 01 [2] 6d 23 [2] 6b 16 [2] 45 16 [2] 7a 0a }

  condition:
    any of them
}