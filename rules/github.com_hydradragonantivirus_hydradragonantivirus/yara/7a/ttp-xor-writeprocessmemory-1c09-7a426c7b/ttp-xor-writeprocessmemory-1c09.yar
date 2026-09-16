rule TTP_XOR_WriteProcessMemory_1c09 {
  strings:
    $key_1c09 = { 4b 7b [2] 79 59 [2] 7f 6c [2] 51 6c [2] 6e 70 }

  condition:
    any of them
}