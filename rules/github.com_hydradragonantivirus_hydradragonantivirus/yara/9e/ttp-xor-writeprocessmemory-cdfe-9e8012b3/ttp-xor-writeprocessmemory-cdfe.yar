rule TTP_XOR_WriteProcessMemory_cdfe {
  strings:
    $key_cdfe = { 9a 8c [2] a8 ae [2] ae 9b [2] 80 9b [2] bf 87 }

  condition:
    any of them
}