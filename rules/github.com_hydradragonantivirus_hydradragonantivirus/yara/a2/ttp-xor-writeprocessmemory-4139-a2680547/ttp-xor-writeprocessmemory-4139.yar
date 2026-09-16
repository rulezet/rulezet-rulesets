rule TTP_XOR_WriteProcessMemory_4139 {
  strings:
    $key_4139 = { 16 4b [2] 24 69 [2] 22 5c [2] 0c 5c [2] 33 40 }

  condition:
    any of them
}