rule TTP_XOR_WriteProcessMemory_2dfe {
  strings:
    $key_2dfe = { 7a 8c [2] 48 ae [2] 4e 9b [2] 60 9b [2] 5f 87 }

  condition:
    any of them
}