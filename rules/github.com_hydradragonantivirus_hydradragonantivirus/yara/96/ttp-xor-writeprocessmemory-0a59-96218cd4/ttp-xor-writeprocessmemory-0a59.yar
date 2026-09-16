rule TTP_XOR_WriteProcessMemory_0a59 {
  strings:
    $key_0a59 = { 5d 2b [2] 6f 09 [2] 69 3c [2] 47 3c [2] 78 20 }

  condition:
    any of them
}