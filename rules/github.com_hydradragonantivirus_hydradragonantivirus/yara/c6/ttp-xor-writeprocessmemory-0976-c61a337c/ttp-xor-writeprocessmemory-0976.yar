rule TTP_XOR_WriteProcessMemory_0976 {
  strings:
    $key_0976 = { 5e 04 [2] 6c 26 [2] 6a 13 [2] 44 13 [2] 7b 0f }

  condition:
    any of them
}