rule TTP_XOR_WriteProcessMemory_e938 {
  strings:
    $key_e938 = { be 4a [2] 8c 68 [2] 8a 5d [2] a4 5d [2] 9b 41 }

  condition:
    any of them
}