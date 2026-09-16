rule TTP_XOR_WriteProcessMemory_2119 {
  strings:
    $key_2119 = { 76 6b [2] 44 49 [2] 42 7c [2] 6c 7c [2] 53 60 }

  condition:
    any of them
}