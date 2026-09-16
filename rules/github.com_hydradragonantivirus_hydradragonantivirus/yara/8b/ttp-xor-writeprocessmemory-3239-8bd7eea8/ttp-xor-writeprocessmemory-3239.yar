rule TTP_XOR_WriteProcessMemory_3239 {
  strings:
    $key_3239 = { 65 4b [2] 57 69 [2] 51 5c [2] 7f 5c [2] 40 40 }

  condition:
    any of them
}