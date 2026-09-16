rule TTP_XOR_WriteProcessMemory_3839 {
  strings:
    $key_3839 = { 6f 4b [2] 5d 69 [2] 5b 5c [2] 75 5c [2] 4a 40 }

  condition:
    any of them
}