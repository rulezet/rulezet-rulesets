rule TTP_XOR_WriteProcessMemory_0dc3 {
  strings:
    $key_0dc3 = { 5a b1 [2] 68 93 [2] 6e a6 [2] 40 a6 [2] 7f ba }

  condition:
    any of them
}