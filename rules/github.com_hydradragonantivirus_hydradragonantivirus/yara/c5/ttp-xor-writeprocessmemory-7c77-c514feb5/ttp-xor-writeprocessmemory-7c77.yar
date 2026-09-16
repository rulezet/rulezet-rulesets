rule TTP_XOR_WriteProcessMemory_7c77 {
  strings:
    $key_7c77 = { 2b 05 [2] 19 27 [2] 1f 12 [2] 31 12 [2] 0e 0e }

  condition:
    any of them
}