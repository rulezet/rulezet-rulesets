rule TTP_XOR_WriteProcessMemory_f949 {
  strings:
    $key_f949 = { ae 3b [2] 9c 19 [2] 9a 2c [2] b4 2c [2] 8b 30 }

  condition:
    any of them
}