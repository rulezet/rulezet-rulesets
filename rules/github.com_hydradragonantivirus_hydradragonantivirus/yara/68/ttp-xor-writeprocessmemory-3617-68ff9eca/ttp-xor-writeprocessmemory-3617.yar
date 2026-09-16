rule TTP_XOR_WriteProcessMemory_3617 {
  strings:
    $key_3617 = { 61 65 [2] 53 47 [2] 55 72 [2] 7b 72 [2] 44 6e }

  condition:
    any of them
}