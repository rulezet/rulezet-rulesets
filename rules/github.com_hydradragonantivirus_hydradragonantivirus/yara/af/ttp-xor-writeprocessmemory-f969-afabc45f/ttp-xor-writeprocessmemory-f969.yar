rule TTP_XOR_WriteProcessMemory_f969 {
  strings:
    $key_f969 = { ae 1b [2] 9c 39 [2] 9a 0c [2] b4 0c [2] 8b 10 }

  condition:
    any of them
}