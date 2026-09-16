rule TTP_XOR_WriteProcessMemory_e309 {
  strings:
    $key_e309 = { b4 7b [2] 86 59 [2] 80 6c [2] ae 6c [2] 91 70 }

  condition:
    any of them
}