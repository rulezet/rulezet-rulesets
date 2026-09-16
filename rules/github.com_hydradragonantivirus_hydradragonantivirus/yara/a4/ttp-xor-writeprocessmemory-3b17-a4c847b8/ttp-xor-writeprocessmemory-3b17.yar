rule TTP_XOR_WriteProcessMemory_3b17 {
  strings:
    $key_3b17 = { 6c 65 [2] 5e 47 [2] 58 72 [2] 76 72 [2] 49 6e }

  condition:
    any of them
}