rule TTP_XOR_WriteProcessMemory_0921 {
  strings:
    $key_0921 = { 5e 53 [2] 6c 71 [2] 6a 44 [2] 44 44 [2] 7b 58 }

  condition:
    any of them
}