rule TTP_XOR_WriteProcessMemory_06bc {
  strings:
    $key_06bc = { 51 ce [2] 63 ec [2] 65 d9 [2] 4b d9 [2] 74 c5 }

  condition:
    any of them
}