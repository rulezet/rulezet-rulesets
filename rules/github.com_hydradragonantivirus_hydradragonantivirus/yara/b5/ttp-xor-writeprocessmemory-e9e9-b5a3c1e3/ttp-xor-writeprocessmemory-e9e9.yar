rule TTP_XOR_WriteProcessMemory_e9e9 {
  strings:
    $key_e9e9 = { be 9b [2] 8c b9 [2] 8a 8c [2] a4 8c [2] 9b 90 }

  condition:
    any of them
}