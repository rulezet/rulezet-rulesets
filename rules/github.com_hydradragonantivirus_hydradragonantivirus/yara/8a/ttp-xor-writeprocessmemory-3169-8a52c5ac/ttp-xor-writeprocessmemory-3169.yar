rule TTP_XOR_WriteProcessMemory_3169 {
  strings:
    $key_3169 = { 66 1b [2] 54 39 [2] 52 0c [2] 7c 0c [2] 43 10 }

  condition:
    any of them
}