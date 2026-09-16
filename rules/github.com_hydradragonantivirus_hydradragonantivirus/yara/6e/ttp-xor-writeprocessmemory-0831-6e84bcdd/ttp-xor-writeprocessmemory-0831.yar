rule TTP_XOR_WriteProcessMemory_0831 {
  strings:
    $key_0831 = { 5f 43 [2] 6d 61 [2] 6b 54 [2] 45 54 [2] 7a 48 }

  condition:
    any of them
}