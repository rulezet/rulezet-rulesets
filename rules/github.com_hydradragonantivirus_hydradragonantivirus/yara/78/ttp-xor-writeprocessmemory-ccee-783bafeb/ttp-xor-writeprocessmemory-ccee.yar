rule TTP_XOR_WriteProcessMemory_ccee {
  strings:
    $key_ccee = { 9b 9c [2] a9 be [2] af 8b [2] 81 8b [2] be 97 }

  condition:
    any of them
}