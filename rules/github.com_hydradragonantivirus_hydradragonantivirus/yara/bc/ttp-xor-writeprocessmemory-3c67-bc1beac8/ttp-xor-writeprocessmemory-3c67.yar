rule TTP_XOR_WriteProcessMemory_3c67 {
  strings:
    $key_3c67 = { 6b 15 [2] 59 37 [2] 5f 02 [2] 71 02 [2] 4e 1e }

  condition:
    any of them
}