rule TTP_XOR_WriteProcessMemory_2d11 {
  strings:
    $key_2d11 = { 7a 63 [2] 48 41 [2] 4e 74 [2] 60 74 [2] 5f 68 }

  condition:
    any of them
}