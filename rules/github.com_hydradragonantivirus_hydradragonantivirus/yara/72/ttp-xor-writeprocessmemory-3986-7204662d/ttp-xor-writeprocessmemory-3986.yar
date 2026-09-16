rule TTP_XOR_WriteProcessMemory_3986 {
  strings:
    $key_3986 = { 6e f4 [2] 5c d6 [2] 5a e3 [2] 74 e3 [2] 4b ff }

  condition:
    any of them
}