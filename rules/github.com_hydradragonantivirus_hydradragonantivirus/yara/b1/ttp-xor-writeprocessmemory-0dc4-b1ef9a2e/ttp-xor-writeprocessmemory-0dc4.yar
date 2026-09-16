rule TTP_XOR_WriteProcessMemory_0dc4 {
  strings:
    $key_0dc4 = { 5a b6 [2] 68 94 [2] 6e a1 [2] 40 a1 [2] 7f bd }

  condition:
    any of them
}