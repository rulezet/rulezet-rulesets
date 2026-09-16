rule TTP_XOR_WriteProcessMemory_7334 {
  strings:
    $key_7334 = { 24 46 [2] 16 64 [2] 10 51 [2] 3e 51 [2] 01 4d }

  condition:
    any of them
}