rule TTP_XOR_WriteProcessMemory_6ea3 {
  strings:
    $key_6ea3 = { 39 d1 [2] 0b f3 [2] 0d c6 [2] 23 c6 [2] 1c da }

  condition:
    any of them
}