rule TTP_XOR_WriteProcessMemory_6c33 {
  strings:
    $key_6c33 = { 3b 41 [2] 09 63 [2] 0f 56 [2] 21 56 [2] 1e 4a }

  condition:
    any of them
}