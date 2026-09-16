rule TTP_XOR_WriteProcessMemory_89dc {
  strings:
    $key_89dc = { de ae [2] ec 8c [2] ea b9 [2] c4 b9 [2] fb a5 }

  condition:
    any of them
}