rule TTP_XOR_WriteProcessMemory_2a85 {
  strings:
    $key_2a85 = { 7d f7 [2] 4f d5 [2] 49 e0 [2] 67 e0 [2] 58 fc }

  condition:
    any of them
}