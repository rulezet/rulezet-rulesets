rule TTP_XOR_WriteProcessMemory_7d09 {
  strings:
    $key_7d09 = { 2a 7b [2] 18 59 [2] 1e 6c [2] 30 6c [2] 0f 70 }

  condition:
    any of them
}