rule TTP_XOR_WriteProcessMemory_2873 {
  strings:
    $key_2873 = { 7f 01 [2] 4d 23 [2] 4b 16 [2] 65 16 [2] 5a 0a }

  condition:
    any of them
}