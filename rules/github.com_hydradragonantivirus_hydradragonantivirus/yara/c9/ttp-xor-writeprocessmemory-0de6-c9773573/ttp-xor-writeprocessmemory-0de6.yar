rule TTP_XOR_WriteProcessMemory_0de6 {
  strings:
    $key_0de6 = { 5a 94 [2] 68 b6 [2] 6e 83 [2] 40 83 [2] 7f 9f }

  condition:
    any of them
}