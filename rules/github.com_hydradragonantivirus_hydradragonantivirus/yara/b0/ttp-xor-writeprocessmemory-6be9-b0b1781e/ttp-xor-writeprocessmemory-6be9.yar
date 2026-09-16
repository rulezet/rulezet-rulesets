rule TTP_XOR_WriteProcessMemory_6be9 {
  strings:
    $key_6be9 = { 3c 9b [2] 0e b9 [2] 08 8c [2] 26 8c [2] 19 90 }

  condition:
    any of them
}