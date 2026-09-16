rule TTP_XOR_WriteProcessMemory_2ace {
  strings:
    $key_2ace = { 7d bc [2] 4f 9e [2] 49 ab [2] 67 ab [2] 58 b7 }

  condition:
    any of them
}