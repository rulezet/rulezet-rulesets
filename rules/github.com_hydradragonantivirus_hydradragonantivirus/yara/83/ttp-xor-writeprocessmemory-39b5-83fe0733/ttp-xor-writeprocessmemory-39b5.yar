rule TTP_XOR_WriteProcessMemory_39b5 {
  strings:
    $key_39b5 = { 6e c7 [2] 5c e5 [2] 5a d0 [2] 74 d0 [2] 4b cc }

  condition:
    any of them
}