rule TTP_XOR_WriteProcessMemory_6734 {
  strings:
    $key_6734 = { 30 46 [2] 02 64 [2] 04 51 [2] 2a 51 [2] 15 4d }

  condition:
    any of them
}