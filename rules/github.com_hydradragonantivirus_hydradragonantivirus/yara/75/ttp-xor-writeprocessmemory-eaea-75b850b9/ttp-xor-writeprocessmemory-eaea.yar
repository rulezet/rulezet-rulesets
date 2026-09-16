rule TTP_XOR_WriteProcessMemory_eaea {
  strings:
    $key_eaea = { bd 98 [2] 8f ba [2] 89 8f [2] a7 8f [2] 98 93 }

  condition:
    any of them
}