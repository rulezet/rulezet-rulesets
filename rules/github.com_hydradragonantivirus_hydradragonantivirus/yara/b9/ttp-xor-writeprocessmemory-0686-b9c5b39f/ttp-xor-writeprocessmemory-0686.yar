rule TTP_XOR_WriteProcessMemory_0686 {
  strings:
    $key_0686 = { 51 f4 [2] 63 d6 [2] 65 e3 [2] 4b e3 [2] 74 ff }

  condition:
    any of them
}