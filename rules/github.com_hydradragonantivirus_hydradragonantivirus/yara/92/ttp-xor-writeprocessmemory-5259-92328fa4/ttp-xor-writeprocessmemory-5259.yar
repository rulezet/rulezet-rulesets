rule TTP_XOR_WriteProcessMemory_5259 {
  strings:
    $key_5259 = { 05 2b [2] 37 09 [2] 31 3c [2] 1f 3c [2] 20 20 }

  condition:
    any of them
}