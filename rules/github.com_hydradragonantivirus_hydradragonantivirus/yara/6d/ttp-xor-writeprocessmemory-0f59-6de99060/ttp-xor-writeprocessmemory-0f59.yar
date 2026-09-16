rule TTP_XOR_WriteProcessMemory_0f59 {
  strings:
    $key_0f59 = { 58 2b [2] 6a 09 [2] 6c 3c [2] 42 3c [2] 7d 20 }

  condition:
    any of them
}