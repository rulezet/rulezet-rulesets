rule TTP_XOR_WriteProcessMemory_7e19 {
  strings:
    $key_7e19 = { 29 6b [2] 1b 49 [2] 1d 7c [2] 33 7c [2] 0c 60 }

  condition:
    any of them
}