rule TTP_XOR_WriteProcessMemory_1c39 {
  strings:
    $key_1c39 = { 4b 4b [2] 79 69 [2] 7f 5c [2] 51 5c [2] 6e 40 }

  condition:
    any of them
}