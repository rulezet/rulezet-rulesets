rule TTP_XOR_WriteProcessMemory_6759 {
  strings:
    $key_6759 = { 30 2b [2] 02 09 [2] 04 3c [2] 2a 3c [2] 15 20 }

  condition:
    any of them
}