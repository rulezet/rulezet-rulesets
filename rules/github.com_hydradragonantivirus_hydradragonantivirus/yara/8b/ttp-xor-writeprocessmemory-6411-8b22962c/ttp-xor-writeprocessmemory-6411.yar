rule TTP_XOR_WriteProcessMemory_6411 {
  strings:
    $key_6411 = { 33 63 [2] 01 41 [2] 07 74 [2] 29 74 [2] 16 68 }

  condition:
    any of them
}