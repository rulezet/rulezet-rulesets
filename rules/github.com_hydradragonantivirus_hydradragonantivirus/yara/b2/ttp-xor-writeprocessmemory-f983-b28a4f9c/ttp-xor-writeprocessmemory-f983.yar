rule TTP_XOR_WriteProcessMemory_f983 {
  strings:
    $key_f983 = { ae f1 [2] 9c d3 [2] 9a e6 [2] b4 e6 [2] 8b fa }

  condition:
    any of them
}