rule TTP_XOR_WriteProcessMemory_eb93 {
  strings:
    $key_eb93 = { bc e1 [2] 8e c3 [2] 88 f6 [2] a6 f6 [2] 99 ea }

  condition:
    any of them
}