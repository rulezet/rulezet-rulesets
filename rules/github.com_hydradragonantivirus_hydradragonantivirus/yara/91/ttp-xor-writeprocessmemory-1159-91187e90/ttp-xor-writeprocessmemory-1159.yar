rule TTP_XOR_WriteProcessMemory_1159 {
  strings:
    $key_1159 = { 46 2b [2] 74 09 [2] 72 3c [2] 5c 3c [2] 63 20 }

  condition:
    any of them
}