rule TTP_XOR_WriteProcessMemory_f97c {
  strings:
    $key_f97c = { ae 0e [2] 9c 2c [2] 9a 19 [2] b4 19 [2] 8b 05 }

  condition:
    any of them
}