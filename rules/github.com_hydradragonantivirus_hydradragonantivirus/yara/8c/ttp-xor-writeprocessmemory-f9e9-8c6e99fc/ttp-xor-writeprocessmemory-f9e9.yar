rule TTP_XOR_WriteProcessMemory_f9e9 {
  strings:
    $key_f9e9 = { ae 9b [2] 9c b9 [2] 9a 8c [2] b4 8c [2] 8b 90 }

  condition:
    any of them
}