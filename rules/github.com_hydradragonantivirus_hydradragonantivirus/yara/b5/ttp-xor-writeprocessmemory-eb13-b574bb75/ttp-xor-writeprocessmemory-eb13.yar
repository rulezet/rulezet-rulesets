rule TTP_XOR_WriteProcessMemory_eb13 {
  strings:
    $key_eb13 = { bc 61 [2] 8e 43 [2] 88 76 [2] a6 76 [2] 99 6a }

  condition:
    any of them
}