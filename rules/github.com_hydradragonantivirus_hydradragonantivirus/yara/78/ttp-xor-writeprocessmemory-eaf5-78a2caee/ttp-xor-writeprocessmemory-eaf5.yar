rule TTP_XOR_WriteProcessMemory_eaf5 {
  strings:
    $key_eaf5 = { bd 87 [2] 8f a5 [2] 89 90 [2] a7 90 [2] 98 8c }

  condition:
    any of them
}