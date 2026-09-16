rule TTP_XOR_WriteProcessMemory_fc73 {
  strings:
    $key_fc73 = { ab 01 [2] 99 23 [2] 9f 16 [2] b1 16 [2] 8e 0a }

  condition:
    any of them
}