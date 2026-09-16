rule TTP_XOR_WriteProcessMemory_f909 {
  strings:
    $key_f909 = { ae 7b [2] 9c 59 [2] 9a 6c [2] b4 6c [2] 8b 70 }

  condition:
    any of them
}