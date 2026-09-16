rule TTP_XOR_WriteProcessMemory_6c39 {
  strings:
    $key_6c39 = { 3b 4b [2] 09 69 [2] 0f 5c [2] 21 5c [2] 1e 40 }

  condition:
    any of them
}