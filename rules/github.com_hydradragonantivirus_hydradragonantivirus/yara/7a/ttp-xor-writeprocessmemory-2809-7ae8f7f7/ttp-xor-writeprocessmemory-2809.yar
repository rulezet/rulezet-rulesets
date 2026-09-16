rule TTP_XOR_WriteProcessMemory_2809 {
  strings:
    $key_2809 = { 7f 7b [2] 4d 59 [2] 4b 6c [2] 65 6c [2] 5a 70 }

  condition:
    any of them
}