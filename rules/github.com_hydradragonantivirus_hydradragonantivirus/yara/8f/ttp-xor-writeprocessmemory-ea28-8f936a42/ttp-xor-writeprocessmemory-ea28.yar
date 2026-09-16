rule TTP_XOR_WriteProcessMemory_ea28 {
  strings:
    $key_ea28 = { bd 5a [2] 8f 78 [2] 89 4d [2] a7 4d [2] 98 51 }

  condition:
    any of them
}