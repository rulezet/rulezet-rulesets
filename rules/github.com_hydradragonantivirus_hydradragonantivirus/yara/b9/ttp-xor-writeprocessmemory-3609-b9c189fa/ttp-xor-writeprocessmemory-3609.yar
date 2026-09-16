rule TTP_XOR_WriteProcessMemory_3609 {
  strings:
    $key_3609 = { 61 7b [2] 53 59 [2] 55 6c [2] 7b 6c [2] 44 70 }

  condition:
    any of them
}