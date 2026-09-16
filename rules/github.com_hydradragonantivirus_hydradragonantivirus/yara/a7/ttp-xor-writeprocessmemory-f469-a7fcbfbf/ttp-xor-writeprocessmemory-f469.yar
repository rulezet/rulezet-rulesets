rule TTP_XOR_WriteProcessMemory_f469 {
  strings:
    $key_f469 = { a3 1b [2] 91 39 [2] 97 0c [2] b9 0c [2] 86 10 }

  condition:
    any of them
}