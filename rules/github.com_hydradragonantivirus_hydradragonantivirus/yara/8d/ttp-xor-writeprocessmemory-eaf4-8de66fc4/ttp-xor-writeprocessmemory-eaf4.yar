rule TTP_XOR_WriteProcessMemory_eaf4 {
  strings:
    $key_eaf4 = { bd 86 [2] 8f a4 [2] 89 91 [2] a7 91 [2] 98 8d }

  condition:
    any of them
}