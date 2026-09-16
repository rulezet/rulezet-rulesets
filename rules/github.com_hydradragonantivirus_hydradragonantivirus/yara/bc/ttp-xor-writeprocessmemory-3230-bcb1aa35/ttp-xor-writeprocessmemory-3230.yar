rule TTP_XOR_WriteProcessMemory_3230 {
  strings:
    $key_3230 = { 65 42 [2] 57 60 [2] 51 55 [2] 7f 55 [2] 40 49 }

  condition:
    any of them
}