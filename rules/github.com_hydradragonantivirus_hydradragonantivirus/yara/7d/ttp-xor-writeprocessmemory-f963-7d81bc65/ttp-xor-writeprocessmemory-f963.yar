rule TTP_XOR_WriteProcessMemory_f963 {
  strings:
    $key_f963 = { ae 11 [2] 9c 33 [2] 9a 06 [2] b4 06 [2] 8b 1a }

  condition:
    any of them
}