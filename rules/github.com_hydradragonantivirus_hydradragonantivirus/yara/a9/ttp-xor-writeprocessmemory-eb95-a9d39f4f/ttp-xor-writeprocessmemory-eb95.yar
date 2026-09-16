rule TTP_XOR_WriteProcessMemory_eb95 {
  strings:
    $key_eb95 = { bc e7 [2] 8e c5 [2] 88 f0 [2] a6 f0 [2] 99 ec }

  condition:
    any of them
}