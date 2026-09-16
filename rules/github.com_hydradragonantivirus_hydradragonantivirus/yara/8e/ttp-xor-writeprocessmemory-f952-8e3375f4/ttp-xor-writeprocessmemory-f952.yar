rule TTP_XOR_WriteProcessMemory_f952 {
  strings:
    $key_f952 = { ae 20 [2] 9c 02 [2] 9a 37 [2] b4 37 [2] 8b 2b }

  condition:
    any of them
}