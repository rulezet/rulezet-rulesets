rule TTP_XOR_WriteProcessMemory_2cee {
  strings:
    $key_2cee = { 7b 9c [2] 49 be [2] 4f 8b [2] 61 8b [2] 5e 97 }

  condition:
    any of them
}