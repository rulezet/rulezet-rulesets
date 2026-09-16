rule TTP_XOR_WriteProcessMemory_2959 {
  strings:
    $key_2959 = { 7e 2b [2] 4c 09 [2] 4a 3c [2] 64 3c [2] 5b 20 }

  condition:
    any of them
}