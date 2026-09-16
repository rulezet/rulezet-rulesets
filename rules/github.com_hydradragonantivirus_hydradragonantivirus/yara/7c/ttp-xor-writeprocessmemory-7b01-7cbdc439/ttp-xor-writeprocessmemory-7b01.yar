rule TTP_XOR_WriteProcessMemory_7b01 {
  strings:
    $key_7b01 = { 2c 73 [2] 1e 51 [2] 18 64 [2] 36 64 [2] 09 78 }

  condition:
    any of them
}