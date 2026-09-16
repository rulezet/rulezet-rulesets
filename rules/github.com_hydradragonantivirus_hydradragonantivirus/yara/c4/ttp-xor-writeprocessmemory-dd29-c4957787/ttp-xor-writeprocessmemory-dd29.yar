rule TTP_XOR_WriteProcessMemory_dd29 {
  strings:
    $key_dd29 = { 8a 5b [2] b8 79 [2] be 4c [2] 90 4c [2] af 50 }

  condition:
    any of them
}