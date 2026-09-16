rule TTP_XOR_WriteProcessMemory_2286 {
  strings:
    $key_2286 = { 75 f4 [2] 47 d6 [2] 41 e3 [2] 6f e3 [2] 50 ff }

  condition:
    any of them
}