rule TTP_XOR_WriteProcessMemory_6d01 {
  strings:
    $key_6d01 = { 3a 73 [2] 08 51 [2] 0e 64 [2] 20 64 [2] 1f 78 }

  condition:
    any of them
}