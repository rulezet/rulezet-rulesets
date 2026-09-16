rule TTP_XOR_WriteProcessMemory_69b5 {
  strings:
    $key_69b5 = { 3e c7 [2] 0c e5 [2] 0a d0 [2] 24 d0 [2] 1b cc }

  condition:
    any of them
}