rule TTP_XOR_WriteProcessMemory_3f09 {
  strings:
    $key_3f09 = { 68 7b [2] 5a 59 [2] 5c 6c [2] 72 6c [2] 4d 70 }

  condition:
    any of them
}