rule TTP_XOR_WriteProcessMemory_00d5 {
  strings:
    $key_00d5 = { 57 a7 [2] 65 85 [2] 63 b0 [2] 4d b0 [2] 72 ac }

  condition:
    any of them
}