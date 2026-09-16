rule TTP_XOR_WriteProcessMemory_e909 {
  strings:
    $key_e909 = { be 7b [2] 8c 59 [2] 8a 6c [2] a4 6c [2] 9b 70 }

  condition:
    any of them
}