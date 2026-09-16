rule TTP_XOR_WriteProcessMemory_0430 {
  strings:
    $key_0430 = { 53 42 [2] 61 60 [2] 67 55 [2] 49 55 [2] 76 49 }

  condition:
    any of them
}