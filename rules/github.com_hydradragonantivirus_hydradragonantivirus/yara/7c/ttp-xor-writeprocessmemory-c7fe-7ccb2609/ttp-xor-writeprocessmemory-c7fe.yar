rule TTP_XOR_WriteProcessMemory_c7fe {
  strings:
    $key_c7fe = { 90 8c [2] a2 ae [2] a4 9b [2] 8a 9b [2] b5 87 }

  condition:
    any of them
}