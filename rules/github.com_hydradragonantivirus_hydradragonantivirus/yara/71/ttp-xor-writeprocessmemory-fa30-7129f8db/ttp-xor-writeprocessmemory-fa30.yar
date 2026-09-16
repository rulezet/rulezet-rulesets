rule TTP_XOR_WriteProcessMemory_fa30 {
  strings:
    $key_fa30 = { ad 42 [2] 9f 60 [2] 99 55 [2] b7 55 [2] 88 49 }

  condition:
    any of them
}