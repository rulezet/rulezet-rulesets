rule TTP_XOR_WriteProcessMemory_e2cb {
  strings:
    $key_e2cb = { b5 b9 [2] 87 9b [2] 81 ae [2] af ae [2] 90 b2 }

  condition:
    any of them
}