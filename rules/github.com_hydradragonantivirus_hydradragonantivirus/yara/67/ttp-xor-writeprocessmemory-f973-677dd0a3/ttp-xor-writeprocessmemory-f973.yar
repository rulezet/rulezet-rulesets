rule TTP_XOR_WriteProcessMemory_f973 {
  strings:
    $key_f973 = { ae 01 [2] 9c 23 [2] 9a 16 [2] b4 16 [2] 8b 0a }

  condition:
    any of them
}