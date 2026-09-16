rule TTP_XOR_WriteProcessMemory_e3fe {
  strings:
    $key_e3fe = { b4 8c [2] 86 ae [2] 80 9b [2] ae 9b [2] 91 87 }

  condition:
    any of them
}