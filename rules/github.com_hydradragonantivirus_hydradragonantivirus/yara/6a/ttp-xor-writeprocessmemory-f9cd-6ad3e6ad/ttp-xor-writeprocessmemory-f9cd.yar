rule TTP_XOR_WriteProcessMemory_f9cd {
  strings:
    $key_f9cd = { ae bf [2] 9c 9d [2] 9a a8 [2] b4 a8 [2] 8b b4 }

  condition:
    any of them
}