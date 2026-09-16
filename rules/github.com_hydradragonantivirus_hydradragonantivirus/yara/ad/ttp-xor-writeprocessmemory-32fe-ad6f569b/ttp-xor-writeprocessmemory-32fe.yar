rule TTP_XOR_WriteProcessMemory_32fe {
  strings:
    $key_32fe = { 65 8c [2] 57 ae [2] 51 9b [2] 7f 9b [2] 40 87 }

  condition:
    any of them
}