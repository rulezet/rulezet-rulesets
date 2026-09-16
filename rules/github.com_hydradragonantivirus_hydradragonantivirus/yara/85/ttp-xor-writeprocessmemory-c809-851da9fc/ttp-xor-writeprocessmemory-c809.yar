rule TTP_XOR_WriteProcessMemory_c809 {
  strings:
    $key_c809 = { 9f 7b [2] ad 59 [2] ab 6c [2] 85 6c [2] ba 70 }

  condition:
    any of them
}