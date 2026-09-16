rule TTP_XOR_WriteProcessMemory_26e8 {
  strings:
    $key_26e8 = { 71 9a [2] 43 b8 [2] 45 8d [2] 6b 8d [2] 54 91 }

  condition:
    any of them
}