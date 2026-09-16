rule TTP_XOR_WriteProcessMemory_1c11 {
  strings:
    $key_1c11 = { 4b 63 [2] 79 41 [2] 7f 74 [2] 51 74 [2] 6e 68 }

  condition:
    any of them
}