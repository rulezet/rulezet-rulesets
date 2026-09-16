rule TTP_XOR_WriteProcessMemory_28fe {
  strings:
    $key_28fe = { 7f 8c [2] 4d ae [2] 4b 9b [2] 65 9b [2] 5a 87 }

  condition:
    any of them
}