rule TTP_XOR_WriteProcessMemory_6e09 {
  strings:
    $key_6e09 = { 39 7b [2] 0b 59 [2] 0d 6c [2] 23 6c [2] 1c 70 }

  condition:
    any of them
}