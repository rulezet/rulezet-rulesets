rule TTP_XOR_WriteProcessMemory_3b39 {
  strings:
    $key_3b39 = { 6c 4b [2] 5e 69 [2] 58 5c [2] 76 5c [2] 49 40 }

  condition:
    any of them
}