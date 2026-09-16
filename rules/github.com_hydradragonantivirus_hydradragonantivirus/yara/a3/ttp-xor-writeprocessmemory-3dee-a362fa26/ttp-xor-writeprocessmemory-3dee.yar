rule TTP_XOR_WriteProcessMemory_3dee {
  strings:
    $key_3dee = { 6a 9c [2] 58 be [2] 5e 8b [2] 70 8b [2] 4f 97 }

  condition:
    any of them
}