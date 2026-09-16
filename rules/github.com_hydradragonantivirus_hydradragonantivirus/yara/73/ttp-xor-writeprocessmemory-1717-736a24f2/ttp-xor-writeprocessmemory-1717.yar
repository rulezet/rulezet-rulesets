rule TTP_XOR_WriteProcessMemory_1717 {
  strings:
    $key_1717 = { 40 65 [2] 72 47 [2] 74 72 [2] 5a 72 [2] 65 6e }

  condition:
    any of them
}