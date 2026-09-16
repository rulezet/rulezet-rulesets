rule TTP_XOR_WriteProcessMemory_6d61 {
  strings:
    $key_6d61 = { 3a 13 [2] 08 31 [2] 0e 04 [2] 20 04 [2] 1f 18 }

  condition:
    any of them
}