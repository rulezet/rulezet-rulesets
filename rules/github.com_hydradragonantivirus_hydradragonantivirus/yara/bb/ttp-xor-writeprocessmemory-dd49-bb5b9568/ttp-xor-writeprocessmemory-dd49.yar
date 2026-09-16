rule TTP_XOR_WriteProcessMemory_dd49 {
  strings:
    $key_dd49 = { 8a 3b [2] b8 19 [2] be 2c [2] 90 2c [2] af 30 }

  condition:
    any of them
}