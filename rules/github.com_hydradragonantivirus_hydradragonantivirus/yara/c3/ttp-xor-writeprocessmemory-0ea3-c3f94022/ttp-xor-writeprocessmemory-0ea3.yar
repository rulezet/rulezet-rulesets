rule TTP_XOR_WriteProcessMemory_0ea3 {
  strings:
    $key_0ea3 = { 59 d1 [2] 6b f3 [2] 6d c6 [2] 43 c6 [2] 7c da }

  condition:
    any of them
}