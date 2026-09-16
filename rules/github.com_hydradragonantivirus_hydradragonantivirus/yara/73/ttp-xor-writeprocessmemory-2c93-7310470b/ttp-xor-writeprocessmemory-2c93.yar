rule TTP_XOR_WriteProcessMemory_2c93 {
  strings:
    $key_2c93 = { 7b e1 [2] 49 c3 [2] 4f f6 [2] 61 f6 [2] 5e ea }

  condition:
    any of them
}