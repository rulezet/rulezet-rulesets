rule TTP_XOR_WriteProcessMemory_ef52 {
  strings:
    $key_ef52 = { b8 20 [2] 8a 02 [2] 8c 37 [2] a2 37 [2] 9d 2b }

  condition:
    any of them
}