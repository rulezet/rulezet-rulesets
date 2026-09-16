rule TTP_XOR_WriteProcessMemory_5a39 {
  strings:
    $key_5a39 = { 0d 4b [2] 3f 69 [2] 39 5c [2] 17 5c [2] 28 40 }

  condition:
    any of them
}