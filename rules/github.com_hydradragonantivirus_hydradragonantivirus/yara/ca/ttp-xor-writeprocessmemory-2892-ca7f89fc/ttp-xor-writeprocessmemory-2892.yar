rule TTP_XOR_WriteProcessMemory_2892 {
  strings:
    $key_2892 = { 7f e0 [2] 4d c2 [2] 4b f7 [2] 65 f7 [2] 5a eb }

  condition:
    any of them
}