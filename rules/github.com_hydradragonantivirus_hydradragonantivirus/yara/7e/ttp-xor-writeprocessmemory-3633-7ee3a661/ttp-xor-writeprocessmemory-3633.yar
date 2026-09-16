rule TTP_XOR_WriteProcessMemory_3633 {
  strings:
    $key_3633 = { 61 41 [2] 53 63 [2] 55 56 [2] 7b 56 [2] 44 4a }

  condition:
    any of them
}