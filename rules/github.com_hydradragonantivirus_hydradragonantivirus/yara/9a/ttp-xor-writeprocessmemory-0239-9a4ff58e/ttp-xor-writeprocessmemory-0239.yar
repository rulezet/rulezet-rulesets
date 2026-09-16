rule TTP_XOR_WriteProcessMemory_0239 {
  strings:
    $key_0239 = { 55 4b [2] 67 69 [2] 61 5c [2] 4f 5c [2] 70 40 }

  condition:
    any of them
}