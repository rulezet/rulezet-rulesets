rule TTP_XOR_WriteProcessMemory_f986 {
  strings:
    $key_f986 = { ae f4 [2] 9c d6 [2] 9a e3 [2] b4 e3 [2] 8b ff }

  condition:
    any of them
}