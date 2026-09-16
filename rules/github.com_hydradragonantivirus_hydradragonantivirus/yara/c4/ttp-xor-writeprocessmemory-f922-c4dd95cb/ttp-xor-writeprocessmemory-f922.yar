rule TTP_XOR_WriteProcessMemory_f922 {
  strings:
    $key_f922 = { ae 50 [2] 9c 72 [2] 9a 47 [2] b4 47 [2] 8b 5b }

  condition:
    any of them
}