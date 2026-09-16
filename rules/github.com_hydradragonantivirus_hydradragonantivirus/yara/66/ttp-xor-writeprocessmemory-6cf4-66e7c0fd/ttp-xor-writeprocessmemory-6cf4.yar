rule TTP_XOR_WriteProcessMemory_6cf4 {
  strings:
    $key_6cf4 = { 3b 86 [2] 09 a4 [2] 0f 91 [2] 21 91 [2] 1e 8d }

  condition:
    any of them
}