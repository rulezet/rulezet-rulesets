rule TTP_XOR_WriteProcessMemory_eaff {
  strings:
    $key_eaff = { bd 8d [2] 8f af [2] 89 9a [2] a7 9a [2] 98 86 }

  condition:
    any of them
}