rule TTP_XOR_WriteProcessMemory_29b5 {
  strings:
    $key_29b5 = { 7e c7 [2] 4c e5 [2] 4a d0 [2] 64 d0 [2] 5b cc }

  condition:
    any of them
}