rule TTP_XOR_WriteProcessMemory_3f59 {
  strings:
    $key_3f59 = { 68 2b [2] 5a 09 [2] 5c 3c [2] 72 3c [2] 4d 20 }

  condition:
    any of them
}