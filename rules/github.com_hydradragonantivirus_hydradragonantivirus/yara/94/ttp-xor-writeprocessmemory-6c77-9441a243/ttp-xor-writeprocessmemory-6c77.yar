rule TTP_XOR_WriteProcessMemory_6c77 {
  strings:
    $key_6c77 = { 3b 05 [2] 09 27 [2] 0f 12 [2] 21 12 [2] 1e 0e }

  condition:
    any of them
}