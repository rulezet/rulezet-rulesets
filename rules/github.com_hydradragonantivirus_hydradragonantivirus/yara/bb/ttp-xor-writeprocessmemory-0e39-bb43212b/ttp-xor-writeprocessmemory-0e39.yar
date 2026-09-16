rule TTP_XOR_WriteProcessMemory_0e39 {
  strings:
    $key_0e39 = { 59 4b [2] 6b 69 [2] 6d 5c [2] 43 5c [2] 7c 40 }

  condition:
    any of them
}