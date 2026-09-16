rule TTP_XOR_WriteProcessMemory_0819 {
  strings:
    $key_0819 = { 5f 6b [2] 6d 49 [2] 6b 7c [2] 45 7c [2] 7a 60 }

  condition:
    any of them
}