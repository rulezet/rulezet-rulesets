rule TTP_XOR_WriteProcessMemory_2e19 {
  strings:
    $key_2e19 = { 79 6b [2] 4b 49 [2] 4d 7c [2] 63 7c [2] 5c 60 }

  condition:
    any of them
}