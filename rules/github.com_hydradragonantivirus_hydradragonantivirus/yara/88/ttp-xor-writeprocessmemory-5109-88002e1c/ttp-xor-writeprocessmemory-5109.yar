rule TTP_XOR_WriteProcessMemory_5109 {
  strings:
    $key_5109 = { 06 7b [2] 34 59 [2] 32 6c [2] 1c 6c [2] 23 70 }

  condition:
    any of them
}