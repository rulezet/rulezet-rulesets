rule TTP_XOR_WriteProcessMemory_ef14 {
  strings:
    $key_ef14 = { b8 66 [2] 8a 44 [2] 8c 71 [2] a2 71 [2] 9d 6d }

  condition:
    any of them
}