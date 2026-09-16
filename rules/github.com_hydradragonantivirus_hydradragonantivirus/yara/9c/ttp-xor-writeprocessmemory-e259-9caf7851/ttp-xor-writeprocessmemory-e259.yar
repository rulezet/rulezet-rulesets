rule TTP_XOR_WriteProcessMemory_e259 {
  strings:
    $key_e259 = { b5 2b [2] 87 09 [2] 81 3c [2] af 3c [2] 90 20 }

  condition:
    any of them
}