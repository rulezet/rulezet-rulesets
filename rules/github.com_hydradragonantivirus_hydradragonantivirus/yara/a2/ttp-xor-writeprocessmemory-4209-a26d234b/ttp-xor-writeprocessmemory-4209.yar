rule TTP_XOR_WriteProcessMemory_4209 {
  strings:
    $key_4209 = { 15 7b [2] 27 59 [2] 21 6c [2] 0f 6c [2] 30 70 }

  condition:
    any of them
}