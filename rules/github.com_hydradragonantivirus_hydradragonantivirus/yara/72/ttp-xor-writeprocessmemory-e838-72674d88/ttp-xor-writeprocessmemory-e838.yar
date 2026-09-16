rule TTP_XOR_WriteProcessMemory_e838 {
  strings:
    $key_e838 = { bf 4a [2] 8d 68 [2] 8b 5d [2] a5 5d [2] 9a 41 }

  condition:
    any of them
}