rule TTP_XOR_WriteProcessMemory_c230 {
  strings:
    $key_c230 = { 95 42 [2] a7 60 [2] a1 55 [2] 8f 55 [2] b0 49 }

  condition:
    any of them
}