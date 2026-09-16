rule TTP_XOR_WriteProcessMemory_d894 {
  strings:
    $key_d894 = { 8f e6 [2] bd c4 [2] bb f1 [2] 95 f1 [2] aa ed }

  condition:
    any of them
}