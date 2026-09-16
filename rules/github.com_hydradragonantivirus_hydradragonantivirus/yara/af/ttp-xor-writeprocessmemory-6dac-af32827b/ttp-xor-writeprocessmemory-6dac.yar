rule TTP_XOR_WriteProcessMemory_6dac {
  strings:
    $key_6dac = { 3a de [2] 08 fc [2] 0e c9 [2] 20 c9 [2] 1f d5 }

  condition:
    any of them
}