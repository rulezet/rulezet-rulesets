rule TTP_XOR_WriteProcessMemory_f974 {
  strings:
    $key_f974 = { ae 06 [2] 9c 24 [2] 9a 11 [2] b4 11 [2] 8b 0d }

  condition:
    any of them
}