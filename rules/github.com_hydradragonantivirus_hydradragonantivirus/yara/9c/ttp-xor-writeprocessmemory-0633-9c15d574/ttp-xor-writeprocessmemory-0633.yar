rule TTP_XOR_WriteProcessMemory_0633 {
  strings:
    $key_0633 = { 51 41 [2] 63 63 [2] 65 56 [2] 4b 56 [2] 74 4a }

  condition:
    any of them
}