rule TTP_XOR_WriteProcessMemory_3801 {
  strings:
    $key_3801 = { 6f 73 [2] 5d 51 [2] 5b 64 [2] 75 64 [2] 4a 78 }

  condition:
    any of them
}