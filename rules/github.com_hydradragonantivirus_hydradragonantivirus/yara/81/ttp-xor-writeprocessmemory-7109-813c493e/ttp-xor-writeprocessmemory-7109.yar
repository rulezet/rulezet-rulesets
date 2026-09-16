rule TTP_XOR_WriteProcessMemory_7109 {
  strings:
    $key_7109 = { 26 7b [2] 14 59 [2] 12 6c [2] 3c 6c [2] 03 70 }

  condition:
    any of them
}