rule TTP_XOR_WriteProcessMemory_c030 {
  strings:
    $key_c030 = { 97 42 [2] a5 60 [2] a3 55 [2] 8d 55 [2] b2 49 }

  condition:
    any of them
}