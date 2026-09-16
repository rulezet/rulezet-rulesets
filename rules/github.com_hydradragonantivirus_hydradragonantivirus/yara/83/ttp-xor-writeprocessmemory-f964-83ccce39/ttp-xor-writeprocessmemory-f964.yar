rule TTP_XOR_WriteProcessMemory_f964 {
  strings:
    $key_f964 = { ae 16 [2] 9c 34 [2] 9a 01 [2] b4 01 [2] 8b 1d }

  condition:
    any of them
}