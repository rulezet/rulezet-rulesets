rule TTP_XOR_WriteProcessMemory_05fe {
  strings:
    $key_05fe = { 52 8c [2] 60 ae [2] 66 9b [2] 48 9b [2] 77 87 }

  condition:
    any of them
}