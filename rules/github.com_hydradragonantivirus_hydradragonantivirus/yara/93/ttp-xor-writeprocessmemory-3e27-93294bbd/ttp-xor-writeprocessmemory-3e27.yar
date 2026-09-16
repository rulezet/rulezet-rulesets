rule TTP_XOR_WriteProcessMemory_3e27 {
  strings:
    $key_3e27 = { 69 55 [2] 5b 77 [2] 5d 42 [2] 73 42 [2] 4c 5e }

  condition:
    any of them
}