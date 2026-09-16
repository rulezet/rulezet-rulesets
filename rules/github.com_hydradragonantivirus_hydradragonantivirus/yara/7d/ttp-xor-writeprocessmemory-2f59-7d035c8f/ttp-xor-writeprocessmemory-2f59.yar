rule TTP_XOR_WriteProcessMemory_2f59 {
  strings:
    $key_2f59 = { 78 2b [2] 4a 09 [2] 4c 3c [2] 62 3c [2] 5d 20 }

  condition:
    any of them
}