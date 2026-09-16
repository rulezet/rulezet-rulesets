rule TTP_XOR_WriteProcessMemory_4a23 {
  strings:
    $key_4a23 = { 1d 51 [2] 2f 73 [2] 29 46 [2] 07 46 [2] 38 5a }

  condition:
    any of them
}