rule TTP_XOR_WriteProcessMemory_4111 {
  strings:
    $key_4111 = { 16 63 [2] 24 41 [2] 22 74 [2] 0c 74 [2] 33 68 }

  condition:
    any of them
}