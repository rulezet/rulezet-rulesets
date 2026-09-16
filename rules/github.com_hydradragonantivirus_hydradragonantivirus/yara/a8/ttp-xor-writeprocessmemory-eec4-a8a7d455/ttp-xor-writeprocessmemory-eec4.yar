rule TTP_XOR_WriteProcessMemory_eec4 {
  strings:
    $key_eec4 = { b9 b6 [2] 8b 94 [2] 8d a1 [2] a3 a1 [2] 9c bd }

  condition:
    any of them
}