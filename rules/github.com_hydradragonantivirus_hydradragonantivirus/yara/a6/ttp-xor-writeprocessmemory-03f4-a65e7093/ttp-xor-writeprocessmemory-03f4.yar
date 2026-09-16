rule TTP_XOR_WriteProcessMemory_03f4 {
  strings:
    $key_03f4 = { 54 86 [2] 66 a4 [2] 60 91 [2] 4e 91 [2] 71 8d }

  condition:
    any of them
}