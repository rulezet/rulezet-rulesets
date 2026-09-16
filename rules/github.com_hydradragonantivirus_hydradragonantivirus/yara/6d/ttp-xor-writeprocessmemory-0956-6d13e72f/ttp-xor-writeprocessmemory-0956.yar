rule TTP_XOR_WriteProcessMemory_0956 {
  strings:
    $key_0956 = { 5e 24 [2] 6c 06 [2] 6a 33 [2] 44 33 [2] 7b 2f }

  condition:
    any of them
}