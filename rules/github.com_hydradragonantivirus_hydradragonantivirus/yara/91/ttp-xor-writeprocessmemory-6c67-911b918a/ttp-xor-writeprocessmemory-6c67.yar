rule TTP_XOR_WriteProcessMemory_6c67 {
  strings:
    $key_6c67 = { 3b 15 [2] 09 37 [2] 0f 02 [2] 21 02 [2] 1e 1e }

  condition:
    any of them
}