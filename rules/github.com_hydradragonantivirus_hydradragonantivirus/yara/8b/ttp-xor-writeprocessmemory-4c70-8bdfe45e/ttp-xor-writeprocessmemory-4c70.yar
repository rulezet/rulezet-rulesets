rule TTP_XOR_WriteProcessMemory_4c70 {
  strings:
    $key_4c70 = { 1b 02 [2] 29 20 [2] 2f 15 [2] 01 15 [2] 3e 09 }

  condition:
    any of them
}