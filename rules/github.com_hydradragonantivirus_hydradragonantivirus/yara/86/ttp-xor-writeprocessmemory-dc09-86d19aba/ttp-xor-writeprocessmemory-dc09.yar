rule TTP_XOR_WriteProcessMemory_dc09 {
  strings:
    $key_dc09 = { 8b 7b [2] b9 59 [2] bf 6c [2] 91 6c [2] ae 70 }

  condition:
    any of them
}