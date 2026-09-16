rule TTP_XOR_WriteProcessMemory_2b65 {
  strings:
    $key_2b65 = { 7c 17 [2] 4e 35 [2] 48 00 [2] 66 00 [2] 59 1c }

  condition:
    any of them
}