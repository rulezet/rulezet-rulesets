rule TTP_XOR_WriteProcessMemory_f409 {
  strings:
    $key_f409 = { a3 7b [2] 91 59 [2] 97 6c [2] b9 6c [2] 86 70 }

  condition:
    any of them
}