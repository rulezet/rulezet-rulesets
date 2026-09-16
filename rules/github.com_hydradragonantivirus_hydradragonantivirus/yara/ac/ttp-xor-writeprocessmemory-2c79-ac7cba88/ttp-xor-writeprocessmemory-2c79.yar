rule TTP_XOR_WriteProcessMemory_2c79 {
  strings:
    $key_2c79 = { 7b 0b [2] 49 29 [2] 4f 1c [2] 61 1c [2] 5e 00 }

  condition:
    any of them
}