rule TTP_XOR_WriteProcessMemory_7c39 {
  strings:
    $key_7c39 = { 2b 4b [2] 19 69 [2] 1f 5c [2] 31 5c [2] 0e 40 }

  condition:
    any of them
}