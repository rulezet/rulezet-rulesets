rule TTP_XOR_WriteProcessMemory_6b17 {
  strings:
    $key_6b17 = { 3c 65 [2] 0e 47 [2] 08 72 [2] 26 72 [2] 19 6e }

  condition:
    any of them
}