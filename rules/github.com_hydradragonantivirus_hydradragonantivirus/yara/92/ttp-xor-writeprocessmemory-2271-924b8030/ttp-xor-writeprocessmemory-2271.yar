rule TTP_XOR_WriteProcessMemory_2271 {
  strings:
    $key_2271 = { 75 03 [2] 47 21 [2] 41 14 [2] 6f 14 [2] 50 08 }

  condition:
    any of them
}