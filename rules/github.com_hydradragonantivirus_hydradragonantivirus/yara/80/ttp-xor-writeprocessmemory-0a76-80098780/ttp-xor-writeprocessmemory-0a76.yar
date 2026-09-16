rule TTP_XOR_WriteProcessMemory_0a76 {
  strings:
    $key_0a76 = { 5d 04 [2] 6f 26 [2] 69 13 [2] 47 13 [2] 78 0f }

  condition:
    any of them
}