rule TTP_XOR_WriteProcessMemory_eaac {
  strings:
    $key_eaac = { bd de [2] 8f fc [2] 89 c9 [2] a7 c9 [2] 98 d5 }

  condition:
    any of them
}