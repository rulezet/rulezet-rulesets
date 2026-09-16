rule TTP_XOR_WriteProcessMemory_f809 {
  strings:
    $key_f809 = { af 7b [2] 9d 59 [2] 9b 6c [2] b5 6c [2] 8a 70 }

  condition:
    any of them
}