rule TTP_XOR_WriteProcessMemory_2b34 {
  strings:
    $key_2b34 = { 7c 46 [2] 4e 64 [2] 48 51 [2] 66 51 [2] 59 4d }

  condition:
    any of them
}