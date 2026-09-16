rule TTP_XOR_WriteProcessMemory_7e59 {
  strings:
    $key_7e59 = { 29 2b [2] 1b 09 [2] 1d 3c [2] 33 3c [2] 0c 20 }

  condition:
    any of them
}