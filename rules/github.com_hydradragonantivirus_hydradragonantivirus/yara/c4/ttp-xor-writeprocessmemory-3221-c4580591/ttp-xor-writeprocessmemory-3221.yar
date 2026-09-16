rule TTP_XOR_WriteProcessMemory_3221 {
  strings:
    $key_3221 = { 65 53 [2] 57 71 [2] 51 44 [2] 7f 44 [2] 40 58 }

  condition:
    any of them
}