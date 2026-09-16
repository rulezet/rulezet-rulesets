rule TTP_XOR_WriteProcessMemory_f319 {
  strings:
    $key_f319 = { a4 6b [2] 96 49 [2] 90 7c [2] be 7c [2] 81 60 }

  condition:
    any of them
}