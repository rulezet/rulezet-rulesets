rule TTP_XOR_WriteProcessMemory_eae5 {
  strings:
    $key_eae5 = { bd 97 [2] 8f b5 [2] 89 80 [2] a7 80 [2] 98 9c }

  condition:
    any of them
}