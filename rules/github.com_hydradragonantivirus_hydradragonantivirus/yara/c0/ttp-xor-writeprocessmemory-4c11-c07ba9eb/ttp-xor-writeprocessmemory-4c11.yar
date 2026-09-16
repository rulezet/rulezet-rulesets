rule TTP_XOR_WriteProcessMemory_4c11 {
  strings:
    $key_4c11 = { 1b 63 [2] 29 41 [2] 2f 74 [2] 01 74 [2] 3e 68 }

  condition:
    any of them
}