rule TTP_XOR_WriteProcessMemory_1939 {
  strings:
    $key_1939 = { 4e 4b [2] 7c 69 [2] 7a 5c [2] 54 5c [2] 6b 40 }

  condition:
    any of them
}