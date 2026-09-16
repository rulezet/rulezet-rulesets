rule TTP_XOR_WriteProcessMemory_3831 {
  strings:
    $key_3831 = { 6f 43 [2] 5d 61 [2] 5b 54 [2] 75 54 [2] 4a 48 }

  condition:
    any of them
}