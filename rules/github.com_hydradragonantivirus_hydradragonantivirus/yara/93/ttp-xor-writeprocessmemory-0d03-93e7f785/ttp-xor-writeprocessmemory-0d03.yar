rule TTP_XOR_WriteProcessMemory_0d03 {
  strings:
    $key_0d03 = { 5a 71 [2] 68 53 [2] 6e 66 [2] 40 66 [2] 7f 7a }

  condition:
    any of them
}