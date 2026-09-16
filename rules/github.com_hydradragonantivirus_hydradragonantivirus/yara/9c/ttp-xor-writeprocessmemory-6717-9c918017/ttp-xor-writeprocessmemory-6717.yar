rule TTP_XOR_WriteProcessMemory_6717 {
  strings:
    $key_6717 = { 30 65 [2] 02 47 [2] 04 72 [2] 2a 72 [2] 15 6e }

  condition:
    any of them
}