rule TTP_XOR_WriteProcessMemory_6b39 {
  strings:
    $key_6b39 = { 3c 4b [2] 0e 69 [2] 08 5c [2] 26 5c [2] 19 40 }

  condition:
    any of them
}