rule TTP_XOR_WriteProcessMemory_ea38 {
  strings:
    $key_ea38 = { bd 4a [2] 8f 68 [2] 89 5d [2] a7 5d [2] 98 41 }

  condition:
    any of them
}