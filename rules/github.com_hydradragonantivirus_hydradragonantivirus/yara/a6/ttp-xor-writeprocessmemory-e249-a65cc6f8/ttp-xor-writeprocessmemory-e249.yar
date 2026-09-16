rule TTP_XOR_WriteProcessMemory_e249 {
  strings:
    $key_e249 = { b5 3b [2] 87 19 [2] 81 2c [2] af 2c [2] 90 30 }

  condition:
    any of them
}