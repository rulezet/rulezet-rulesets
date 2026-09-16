rule TTP_XOR_WriteProcessMemory_1c33 {
  strings:
    $key_1c33 = { 4b 41 [2] 79 63 [2] 7f 56 [2] 51 56 [2] 6e 4a }

  condition:
    any of them
}