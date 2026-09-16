rule TTP_XOR_WriteProcessMemory_3909 {
  strings:
    $key_3909 = { 6e 7b [2] 5c 59 [2] 5a 6c [2] 74 6c [2] 4b 70 }

  condition:
    any of them
}