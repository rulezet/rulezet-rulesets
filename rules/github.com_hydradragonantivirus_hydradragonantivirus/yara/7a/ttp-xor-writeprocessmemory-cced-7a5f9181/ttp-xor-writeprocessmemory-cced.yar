rule TTP_XOR_WriteProcessMemory_cced {
  strings:
    $key_cced = { 9b 9f [2] a9 bd [2] af 88 [2] 81 88 [2] be 94 }

  condition:
    any of them
}