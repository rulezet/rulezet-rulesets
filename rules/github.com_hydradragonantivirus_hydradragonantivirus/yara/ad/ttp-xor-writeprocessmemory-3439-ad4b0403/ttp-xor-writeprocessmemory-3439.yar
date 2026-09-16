rule TTP_XOR_WriteProcessMemory_3439 {
  strings:
    $key_3439 = { 63 4b [2] 51 69 [2] 57 5c [2] 79 5c [2] 46 40 }

  condition:
    any of them
}