rule TTP_XOR_WriteProcessMemory_fc23 {
  strings:
    $key_fc23 = { ab 51 [2] 99 73 [2] 9f 46 [2] b1 46 [2] 8e 5a }

  condition:
    any of them
}