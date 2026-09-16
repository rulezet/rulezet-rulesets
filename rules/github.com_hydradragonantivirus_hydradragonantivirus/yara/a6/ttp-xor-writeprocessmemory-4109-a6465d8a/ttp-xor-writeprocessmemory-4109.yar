rule TTP_XOR_WriteProcessMemory_4109 {
  strings:
    $key_4109 = { 16 7b [2] 24 59 [2] 22 6c [2] 0c 6c [2] 33 70 }

  condition:
    any of them
}