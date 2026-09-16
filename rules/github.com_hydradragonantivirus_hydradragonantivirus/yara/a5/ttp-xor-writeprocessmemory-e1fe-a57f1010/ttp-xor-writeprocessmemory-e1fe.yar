rule TTP_XOR_WriteProcessMemory_e1fe {
  strings:
    $key_e1fe = { b6 8c [2] 84 ae [2] 82 9b [2] ac 9b [2] 93 87 }

  condition:
    any of them
}