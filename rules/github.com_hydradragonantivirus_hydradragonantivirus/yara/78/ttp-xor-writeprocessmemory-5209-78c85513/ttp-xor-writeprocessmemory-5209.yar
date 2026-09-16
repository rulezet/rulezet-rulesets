rule TTP_XOR_WriteProcessMemory_5209 {
  strings:
    $key_5209 = { 05 7b [2] 37 59 [2] 31 6c [2] 1f 6c [2] 20 70 }

  condition:
    any of them
}