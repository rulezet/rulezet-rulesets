rule TTP_XOR_WriteProcessMemory_fec4 {
  strings:
    $key_fec4 = { a9 b6 [2] 9b 94 [2] 9d a1 [2] b3 a1 [2] 8c bd }

  condition:
    any of them
}