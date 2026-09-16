rule TTP_XOR_WriteProcessMemory_e809 {
  strings:
    $key_e809 = { bf 7b [2] 8d 59 [2] 8b 6c [2] a5 6c [2] 9a 70 }

  condition:
    any of them
}