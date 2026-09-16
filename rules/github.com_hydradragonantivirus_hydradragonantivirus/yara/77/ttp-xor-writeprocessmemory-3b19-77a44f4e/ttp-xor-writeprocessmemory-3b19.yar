rule TTP_XOR_WriteProcessMemory_3b19 {
  strings:
    $key_3b19 = { 6c 6b [2] 5e 49 [2] 58 7c [2] 76 7c [2] 49 60 }

  condition:
    any of them
}