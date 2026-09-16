rule TTP_XOR_WriteProcessMemory_f429 {
  strings:
    $key_f429 = { a3 5b [2] 91 79 [2] 97 4c [2] b9 4c [2] 86 50 }

  condition:
    any of them
}