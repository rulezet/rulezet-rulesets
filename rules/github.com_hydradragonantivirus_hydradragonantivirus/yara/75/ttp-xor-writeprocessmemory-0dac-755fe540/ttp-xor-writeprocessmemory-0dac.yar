rule TTP_XOR_WriteProcessMemory_0dac {
  strings:
    $key_0dac = { 5a de [2] 68 fc [2] 6e c9 [2] 40 c9 [2] 7f d5 }

  condition:
    any of them
}