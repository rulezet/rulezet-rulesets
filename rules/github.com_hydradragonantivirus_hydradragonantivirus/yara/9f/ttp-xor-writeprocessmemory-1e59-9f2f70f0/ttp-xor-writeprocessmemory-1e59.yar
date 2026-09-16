rule TTP_XOR_WriteProcessMemory_1e59 {
  strings:
    $key_1e59 = { 49 2b [2] 7b 09 [2] 7d 3c [2] 53 3c [2] 6c 20 }

  condition:
    any of them
}