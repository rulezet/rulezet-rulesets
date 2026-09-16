rule TTP_XOR_WriteProcessMemory_3286 {
  strings:
    $key_3286 = { 65 f4 [2] 57 d6 [2] 51 e3 [2] 7f e3 [2] 40 ff }

  condition:
    any of them
}