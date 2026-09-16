rule TTP_XOR_WriteProcessMemory_2d61 {
  strings:
    $key_2d61 = { 7a 13 [2] 48 31 [2] 4e 04 [2] 60 04 [2] 5f 18 }

  condition:
    any of them
}