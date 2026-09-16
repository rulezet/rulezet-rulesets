rule TTP_XOR_WriteProcessMemory_5a40 {
  strings:
    $key_5a40 = { 0d 32 [2] 3f 10 [2] 39 25 [2] 17 25 [2] 28 39 }

  condition:
    any of them
}