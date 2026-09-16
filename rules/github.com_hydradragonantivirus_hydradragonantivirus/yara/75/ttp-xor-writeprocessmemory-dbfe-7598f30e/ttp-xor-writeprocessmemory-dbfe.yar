rule TTP_XOR_WriteProcessMemory_dbfe {
  strings:
    $key_dbfe = { 8c 8c [2] be ae [2] b8 9b [2] 96 9b [2] a9 87 }

  condition:
    any of them
}