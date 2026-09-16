rule TTP_XOR_WriteProcessMemory_39b3 {
  strings:
    $key_39b3 = { 6e c1 [2] 5c e3 [2] 5a d6 [2] 74 d6 [2] 4b ca }

  condition:
    any of them
}