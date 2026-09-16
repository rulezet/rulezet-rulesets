rule TTP_XOR_WriteProcessMemory_d137 {
  strings:
    $key_d137 = { 86 45 [2] b4 67 [2] b2 52 [2] 9c 52 [2] a3 4e }

  condition:
    any of them
}