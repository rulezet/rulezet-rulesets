rule TTP_XOR_WriteProcessMemory_7717 {
  strings:
    $key_7717 = { 20 65 [2] 12 47 [2] 14 72 [2] 3a 72 [2] 05 6e }

  condition:
    any of them
}