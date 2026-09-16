rule TTP_XOR_WriteProcessMemory_2bb2 {
  strings:
    $key_2bb2 = { 7c c0 [2] 4e e2 [2] 48 d7 [2] 66 d7 [2] 59 cb }

  condition:
    any of them
}