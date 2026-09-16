rule TTP_XOR_WriteProcessMemory_2b74 {
  strings:
    $key_2b74 = { 7c 06 [2] 4e 24 [2] 48 11 [2] 66 11 [2] 59 0d }

  condition:
    any of them
}