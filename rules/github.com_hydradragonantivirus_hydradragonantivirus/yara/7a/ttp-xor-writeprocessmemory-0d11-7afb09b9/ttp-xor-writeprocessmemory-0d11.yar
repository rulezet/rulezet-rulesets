rule TTP_XOR_WriteProcessMemory_0d11 {
  strings:
    $key_0d11 = { 5a 63 [2] 68 41 [2] 6e 74 [2] 40 74 [2] 7f 68 }

  condition:
    any of them
}