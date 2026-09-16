rule TTP_XOR_WriteProcessMemory_f9c8 {
  strings:
    $key_f9c8 = { ae ba [2] 9c 98 [2] 9a ad [2] b4 ad [2] 8b b1 }

  condition:
    any of them
}