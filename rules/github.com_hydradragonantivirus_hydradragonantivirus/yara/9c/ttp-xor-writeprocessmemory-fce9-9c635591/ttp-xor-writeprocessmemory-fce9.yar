rule TTP_XOR_WriteProcessMemory_fce9 {
  strings:
    $key_fce9 = { ab 9b [2] 99 b9 [2] 9f 8c [2] b1 8c [2] 8e 90 }

  condition:
    any of them
}