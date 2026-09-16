rule TTP_XOR_WriteProcessMemory_0670 {
  strings:
    $key_0670 = { 51 02 [2] 63 20 [2] 65 15 [2] 4b 15 [2] 74 09 }

  condition:
    any of them
}