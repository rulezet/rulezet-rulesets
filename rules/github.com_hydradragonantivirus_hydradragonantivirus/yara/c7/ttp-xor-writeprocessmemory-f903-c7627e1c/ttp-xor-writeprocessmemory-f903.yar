rule TTP_XOR_WriteProcessMemory_f903 {
  strings:
    $key_f903 = { ae 71 [2] 9c 53 [2] 9a 66 [2] b4 66 [2] 8b 7a }

  condition:
    any of them
}