rule TTP_XOR_WriteProcessMemory_06ee {
  strings:
    $key_06ee = { 51 9c [2] 63 be [2] 65 8b [2] 4b 8b [2] 74 97 }

  condition:
    any of them
}