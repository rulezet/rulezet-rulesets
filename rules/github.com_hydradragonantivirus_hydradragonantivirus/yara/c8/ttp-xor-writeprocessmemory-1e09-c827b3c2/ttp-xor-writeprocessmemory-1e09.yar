rule TTP_XOR_WriteProcessMemory_1e09 {
  strings:
    $key_1e09 = { 49 7b [2] 7b 59 [2] 7d 6c [2] 53 6c [2] 6c 70 }

  condition:
    any of them
}