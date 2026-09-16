rule TTP_XOR_WriteProcessMemory_ea0c {
  strings:
    $key_ea0c = { bd 7e [2] 8f 5c [2] 89 69 [2] a7 69 [2] 98 75 }

  condition:
    any of them
}