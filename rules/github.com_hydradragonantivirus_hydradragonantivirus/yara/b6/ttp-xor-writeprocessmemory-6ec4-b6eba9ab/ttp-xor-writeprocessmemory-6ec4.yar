rule TTP_XOR_WriteProcessMemory_6ec4 {
  strings:
    $key_6ec4 = { 39 b6 [2] 0b 94 [2] 0d a1 [2] 23 a1 [2] 1c bd }

  condition:
    any of them
}