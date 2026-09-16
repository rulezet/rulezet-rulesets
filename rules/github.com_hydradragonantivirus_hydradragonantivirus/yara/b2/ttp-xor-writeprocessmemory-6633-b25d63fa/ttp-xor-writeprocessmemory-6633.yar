rule TTP_XOR_WriteProcessMemory_6633 {
  strings:
    $key_6633 = { 31 41 [2] 03 63 [2] 05 56 [2] 2b 56 [2] 14 4a }

  condition:
    any of them
}