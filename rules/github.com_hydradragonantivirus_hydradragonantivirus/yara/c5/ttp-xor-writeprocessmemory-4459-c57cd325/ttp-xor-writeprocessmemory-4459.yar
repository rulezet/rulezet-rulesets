rule TTP_XOR_WriteProcessMemory_4459 {
  strings:
    $key_4459 = { 13 2b [2] 21 09 [2] 27 3c [2] 09 3c [2] 36 20 }

  condition:
    any of them
}