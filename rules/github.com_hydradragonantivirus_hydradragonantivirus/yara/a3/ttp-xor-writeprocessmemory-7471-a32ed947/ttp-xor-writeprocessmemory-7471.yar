rule TTP_XOR_WriteProcessMemory_7471 {
  strings:
    $key_7471 = { 23 03 [2] 11 21 [2] 17 14 [2] 39 14 [2] 06 08 }

  condition:
    any of them
}