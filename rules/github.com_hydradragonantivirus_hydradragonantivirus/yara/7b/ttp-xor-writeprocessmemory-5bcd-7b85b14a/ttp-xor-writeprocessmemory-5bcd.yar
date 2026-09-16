rule TTP_XOR_WriteProcessMemory_5bcd {
  strings:
    $key_5bcd = { 0c bf [2] 3e 9d [2] 38 a8 [2] 16 a8 [2] 29 b4 }

  condition:
    any of them
}