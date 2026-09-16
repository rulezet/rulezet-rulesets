rule TTP_XOR_WriteProcessMemory_45fe {
  strings:
    $key_45fe = { 12 8c [2] 20 ae [2] 26 9b [2] 08 9b [2] 37 87 }

  condition:
    any of them
}