rule TTP_XOR_WriteProcessMemory_1039 {
  strings:
    $key_1039 = { 47 4b [2] 75 69 [2] 73 5c [2] 5d 5c [2] 62 40 }

  condition:
    any of them
}