rule TTP_XOR_WriteProcessMemory_7231 {
  strings:
    $key_7231 = { 25 43 [2] 17 61 [2] 11 54 [2] 3f 54 [2] 00 48 }

  condition:
    any of them
}