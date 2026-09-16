rule TTP_XOR_WriteProcessMemory_2109 {
  strings:
    $key_2109 = { 76 7b [2] 44 59 [2] 42 6c [2] 6c 6c [2] 53 70 }

  condition:
    any of them
}