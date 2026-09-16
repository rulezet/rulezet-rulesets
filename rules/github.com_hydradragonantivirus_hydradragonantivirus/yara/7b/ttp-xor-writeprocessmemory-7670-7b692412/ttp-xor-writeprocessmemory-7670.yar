rule TTP_XOR_WriteProcessMemory_7670 {
  strings:
    $key_7670 = { 21 02 [2] 13 20 [2] 15 15 [2] 3b 15 [2] 04 09 }

  condition:
    any of them
}