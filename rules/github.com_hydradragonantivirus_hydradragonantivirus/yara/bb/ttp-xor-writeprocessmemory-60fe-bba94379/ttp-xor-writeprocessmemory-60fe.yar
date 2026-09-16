rule TTP_XOR_WriteProcessMemory_60fe {
  strings:
    $key_60fe = { 37 8c [2] 05 ae [2] 03 9b [2] 2d 9b [2] 12 87 }

  condition:
    any of them
}