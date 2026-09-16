rule TTP_XOR_WriteProcessMemory_fe59 {
  strings:
    $key_fe59 = { a9 2b [2] 9b 09 [2] 9d 3c [2] b3 3c [2] 8c 20 }

  condition:
    any of them
}