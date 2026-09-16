rule TTP_XOR_WriteProcessMemory_6c79 {
  strings:
    $key_6c79 = { 3b 0b [2] 09 29 [2] 0f 1c [2] 21 1c [2] 1e 00 }

  condition:
    any of them
}