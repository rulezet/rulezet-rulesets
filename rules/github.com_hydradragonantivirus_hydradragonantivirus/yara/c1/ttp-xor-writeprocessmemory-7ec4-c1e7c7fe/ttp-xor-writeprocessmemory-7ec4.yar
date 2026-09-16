rule TTP_XOR_WriteProcessMemory_7ec4 {
  strings:
    $key_7ec4 = { 29 b6 [2] 1b 94 [2] 1d a1 [2] 33 a1 [2] 0c bd }

  condition:
    any of them
}