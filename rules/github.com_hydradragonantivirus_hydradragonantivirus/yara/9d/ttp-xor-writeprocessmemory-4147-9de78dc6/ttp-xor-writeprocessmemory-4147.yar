rule TTP_XOR_WriteProcessMemory_4147 {
  strings:
    $key_4147 = { 16 35 [2] 24 17 [2] 22 22 [2] 0c 22 [2] 33 3e }

  condition:
    any of them
}