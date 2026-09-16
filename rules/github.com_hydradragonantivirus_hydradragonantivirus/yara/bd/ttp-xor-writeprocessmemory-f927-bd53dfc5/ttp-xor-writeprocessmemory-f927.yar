rule TTP_XOR_WriteProcessMemory_f927 {
  strings:
    $key_f927 = { ae 55 [2] 9c 77 [2] 9a 42 [2] b4 42 [2] 8b 5e }

  condition:
    any of them
}