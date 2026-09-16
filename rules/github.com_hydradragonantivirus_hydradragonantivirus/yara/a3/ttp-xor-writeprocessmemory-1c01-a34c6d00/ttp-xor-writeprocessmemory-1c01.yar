rule TTP_XOR_WriteProcessMemory_1c01 {
  strings:
    $key_1c01 = { 4b 73 [2] 79 51 [2] 7f 64 [2] 51 64 [2] 6e 78 }

  condition:
    any of them
}