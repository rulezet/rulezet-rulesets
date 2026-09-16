rule TTP_XOR_WriteProcessMemory_0de0 {
  strings:
    $key_0de0 = { 5a 92 [2] 68 b0 [2] 6e 85 [2] 40 85 [2] 7f 99 }

  condition:
    any of them
}