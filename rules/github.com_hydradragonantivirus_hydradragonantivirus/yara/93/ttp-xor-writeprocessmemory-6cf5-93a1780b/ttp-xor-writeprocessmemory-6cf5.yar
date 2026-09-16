rule TTP_XOR_WriteProcessMemory_6cf5 {
  strings:
    $key_6cf5 = { 3b 87 [2] 09 a5 [2] 0f 90 [2] 21 90 [2] 1e 8c }

  condition:
    any of them
}