rule TTP_XOR_WriteProcessMemory_3869 {
  strings:
    $key_3869 = { 6f 1b [2] 5d 39 [2] 5b 0c [2] 75 0c [2] 4a 10 }

  condition:
    any of them
}