rule TTP_XOR_WriteProcessMemory_1959 {
  strings:
    $key_1959 = { 4e 2b [2] 7c 09 [2] 7a 3c [2] 54 3c [2] 6b 20 }

  condition:
    any of them
}