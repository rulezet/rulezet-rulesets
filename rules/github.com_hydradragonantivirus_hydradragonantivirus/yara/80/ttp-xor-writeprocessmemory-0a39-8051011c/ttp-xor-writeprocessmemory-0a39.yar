rule TTP_XOR_WriteProcessMemory_0a39 {
  strings:
    $key_0a39 = { 5d 4b [2] 6f 69 [2] 69 5c [2] 47 5c [2] 78 40 }

  condition:
    any of them
}