rule TTP_XOR_WriteProcessMemory_7f09 {
  strings:
    $key_7f09 = { 28 7b [2] 1a 59 [2] 1c 6c [2] 32 6c [2] 0d 70 }

  condition:
    any of them
}