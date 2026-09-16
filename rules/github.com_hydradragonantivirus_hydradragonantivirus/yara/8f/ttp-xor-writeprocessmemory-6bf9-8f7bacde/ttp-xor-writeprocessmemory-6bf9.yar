rule TTP_XOR_WriteProcessMemory_6bf9 {
  strings:
    $key_6bf9 = { 3c 8b [2] 0e a9 [2] 08 9c [2] 26 9c [2] 19 80 }

  condition:
    any of them
}