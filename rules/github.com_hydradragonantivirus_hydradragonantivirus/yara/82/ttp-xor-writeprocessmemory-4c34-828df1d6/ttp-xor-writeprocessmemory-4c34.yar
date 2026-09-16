rule TTP_XOR_WriteProcessMemory_4c34 {
  strings:
    $key_4c34 = { 1b 46 [2] 29 64 [2] 2f 51 [2] 01 51 [2] 3e 4d }

  condition:
    any of them
}