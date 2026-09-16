rule TTP_XOR_WriteProcessMemory_5d09 {
  strings:
    $key_5d09 = { 0a 7b [2] 38 59 [2] 3e 6c [2] 10 6c [2] 2f 70 }

  condition:
    any of them
}