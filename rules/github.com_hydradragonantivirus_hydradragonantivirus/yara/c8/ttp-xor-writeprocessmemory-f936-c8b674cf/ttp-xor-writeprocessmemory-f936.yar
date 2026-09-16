rule TTP_XOR_WriteProcessMemory_f936 {
  strings:
    $key_f936 = { ae 44 [2] 9c 66 [2] 9a 53 [2] b4 53 [2] 8b 4f }

  condition:
    any of them
}