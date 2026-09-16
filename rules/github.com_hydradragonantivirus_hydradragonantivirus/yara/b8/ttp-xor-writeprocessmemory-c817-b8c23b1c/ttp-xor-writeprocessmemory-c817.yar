rule TTP_XOR_WriteProcessMemory_c817 {
  strings:
    $key_c817 = { 9f 65 [2] ad 47 [2] ab 72 [2] 85 72 [2] ba 6e }

  condition:
    any of them
}