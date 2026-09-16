rule TTP_XOR_WriteProcessMemory_48f4 {
  strings:
    $key_48f4 = { 1f 86 [2] 2d a4 [2] 2b 91 [2] 05 91 [2] 3a 8d }

  condition:
    any of them
}