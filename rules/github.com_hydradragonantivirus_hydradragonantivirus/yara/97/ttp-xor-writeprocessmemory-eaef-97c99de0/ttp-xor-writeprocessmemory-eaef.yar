rule TTP_XOR_WriteProcessMemory_eaef {
  strings:
    $key_eaef = { bd 9d [2] 8f bf [2] 89 8a [2] a7 8a [2] 98 96 }

  condition:
    any of them
}