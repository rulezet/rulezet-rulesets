rule TTP_XOR_WriteProcessMemory_eb94 {
  strings:
    $key_eb94 = { bc e6 [2] 8e c4 [2] 88 f1 [2] a6 f1 [2] 99 ed }

  condition:
    any of them
}