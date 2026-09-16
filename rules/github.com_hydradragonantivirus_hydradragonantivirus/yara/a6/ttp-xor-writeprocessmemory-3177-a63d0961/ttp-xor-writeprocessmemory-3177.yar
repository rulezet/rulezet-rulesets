rule TTP_XOR_WriteProcessMemory_3177 {
  strings:
    $key_3177 = { 66 05 [2] 54 27 [2] 52 12 [2] 7c 12 [2] 43 0e }

  condition:
    any of them
}