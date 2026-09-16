rule TTP_XOR_WriteProcessMemory_2b63 {
  strings:
    $key_2b63 = { 7c 11 [2] 4e 33 [2] 48 06 [2] 66 06 [2] 59 1a }

  condition:
    any of them
}