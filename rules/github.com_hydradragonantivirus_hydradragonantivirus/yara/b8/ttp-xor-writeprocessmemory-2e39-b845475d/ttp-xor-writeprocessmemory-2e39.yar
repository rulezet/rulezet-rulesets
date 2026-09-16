rule TTP_XOR_WriteProcessMemory_2e39 {
  strings:
    $key_2e39 = { 79 4b [2] 4b 69 [2] 4d 5c [2] 63 5c [2] 5c 40 }

  condition:
    any of them
}