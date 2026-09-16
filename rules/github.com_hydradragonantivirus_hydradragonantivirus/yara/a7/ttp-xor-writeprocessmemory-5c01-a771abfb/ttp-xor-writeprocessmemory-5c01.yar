rule TTP_XOR_WriteProcessMemory_5c01 {
  strings:
    $key_5c01 = { 0b 73 [2] 39 51 [2] 3f 64 [2] 11 64 [2] 2e 78 }

  condition:
    any of them
}