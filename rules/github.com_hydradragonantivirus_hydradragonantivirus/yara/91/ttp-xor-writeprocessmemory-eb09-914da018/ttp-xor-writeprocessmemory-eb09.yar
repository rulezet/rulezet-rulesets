rule TTP_XOR_WriteProcessMemory_eb09 {
  strings:
    $key_eb09 = { bc 7b [2] 8e 59 [2] 88 6c [2] a6 6c [2] 99 70 }

  condition:
    any of them
}