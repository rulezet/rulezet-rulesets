rule TTP_XOR_WriteProcessMemory_0480 {
  strings:
    $key_0480 = { 53 f2 [2] 61 d0 [2] 67 e5 [2] 49 e5 [2] 76 f9 }

  condition:
    any of them
}