rule TTP_XOR_WriteProcessMemory_5a47 {
  strings:
    $key_5a47 = { 0d 35 [2] 3f 17 [2] 39 22 [2] 17 22 [2] 28 3e }

  condition:
    any of them
}