rule TTP_XOR_WriteProcessMemory_2a31 {
  strings:
    $key_2a31 = { 7d 43 [2] 4f 61 [2] 49 54 [2] 67 54 [2] 58 48 }

  condition:
    any of them
}