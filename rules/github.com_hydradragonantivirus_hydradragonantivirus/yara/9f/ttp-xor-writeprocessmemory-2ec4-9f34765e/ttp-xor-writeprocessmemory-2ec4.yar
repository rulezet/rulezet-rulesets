rule TTP_XOR_WriteProcessMemory_2ec4 {
  strings:
    $key_2ec4 = { 79 b6 [2] 4b 94 [2] 4d a1 [2] 63 a1 [2] 5c bd }

  condition:
    any of them
}