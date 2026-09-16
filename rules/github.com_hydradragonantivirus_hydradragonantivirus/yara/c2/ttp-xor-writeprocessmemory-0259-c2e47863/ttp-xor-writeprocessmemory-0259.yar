rule TTP_XOR_WriteProcessMemory_0259 {
  strings:
    $key_0259 = { 55 2b [2] 67 09 [2] 61 3c [2] 4f 3c [2] 70 20 }

  condition:
    any of them
}