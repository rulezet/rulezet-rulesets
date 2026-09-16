rule TTP_XOR_WriteProcessMemory_3219 {
  strings:
    $key_3219 = { 65 6b [2] 57 49 [2] 51 7c [2] 7f 7c [2] 40 60 }

  condition:
    any of them
}