rule TTP_XOR_WriteProcessMemory_2f09 {
  strings:
    $key_2f09 = { 78 7b [2] 4a 59 [2] 4c 6c [2] 62 6c [2] 5d 70 }

  condition:
    any of them
}