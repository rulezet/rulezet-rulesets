rule TTP_XOR_WriteProcessMemory_e2fe {
  strings:
    $key_e2fe = { b5 8c [2] 87 ae [2] 81 9b [2] af 9b [2] 90 87 }

  condition:
    any of them
}