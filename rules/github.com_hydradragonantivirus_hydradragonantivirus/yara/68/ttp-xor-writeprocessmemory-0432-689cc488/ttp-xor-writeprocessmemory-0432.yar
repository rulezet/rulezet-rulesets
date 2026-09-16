rule TTP_XOR_WriteProcessMemory_0432 {
  strings:
    $key_0432 = { 53 40 [2] 61 62 [2] 67 57 [2] 49 57 [2] 76 4b }

  condition:
    any of them
}