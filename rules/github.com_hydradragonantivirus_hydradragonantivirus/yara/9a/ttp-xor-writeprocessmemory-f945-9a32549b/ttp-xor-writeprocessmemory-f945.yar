rule TTP_XOR_WriteProcessMemory_f945 {
  strings:
    $key_f945 = { ae 37 [2] 9c 15 [2] 9a 20 [2] b4 20 [2] 8b 3c }

  condition:
    any of them
}