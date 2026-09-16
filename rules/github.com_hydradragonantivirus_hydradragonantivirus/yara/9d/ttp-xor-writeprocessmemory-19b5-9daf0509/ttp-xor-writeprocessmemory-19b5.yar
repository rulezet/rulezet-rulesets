rule TTP_XOR_WriteProcessMemory_19b5 {
  strings:
    $key_19b5 = { 4e c7 [2] 7c e5 [2] 7a d0 [2] 54 d0 [2] 6b cc }

  condition:
    any of them
}