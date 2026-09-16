rule TTP_XOR_WriteProcessMemory_7e09 {
  strings:
    $key_7e09 = { 29 7b [2] 1b 59 [2] 1d 6c [2] 33 6c [2] 0c 70 }

  condition:
    any of them
}