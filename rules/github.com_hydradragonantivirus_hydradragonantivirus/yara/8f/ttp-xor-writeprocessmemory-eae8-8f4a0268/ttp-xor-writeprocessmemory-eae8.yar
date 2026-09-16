rule TTP_XOR_WriteProcessMemory_eae8 {
  strings:
    $key_eae8 = { bd 9a [2] 8f b8 [2] 89 8d [2] a7 8d [2] 98 91 }

  condition:
    any of them
}