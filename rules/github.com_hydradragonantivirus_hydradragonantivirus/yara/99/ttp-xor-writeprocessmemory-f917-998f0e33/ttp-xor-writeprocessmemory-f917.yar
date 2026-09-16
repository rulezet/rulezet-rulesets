rule TTP_XOR_WriteProcessMemory_f917 {
  strings:
    $key_f917 = { ae 65 [2] 9c 47 [2] 9a 72 [2] b4 72 [2] 8b 6e }

  condition:
    any of them
}