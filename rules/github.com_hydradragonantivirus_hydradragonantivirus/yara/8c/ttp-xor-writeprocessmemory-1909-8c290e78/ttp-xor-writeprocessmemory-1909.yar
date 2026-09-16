rule TTP_XOR_WriteProcessMemory_1909 {
  strings:
    $key_1909 = { 4e 7b [2] 7c 59 [2] 7a 6c [2] 54 6c [2] 6b 70 }

  condition:
    any of them
}