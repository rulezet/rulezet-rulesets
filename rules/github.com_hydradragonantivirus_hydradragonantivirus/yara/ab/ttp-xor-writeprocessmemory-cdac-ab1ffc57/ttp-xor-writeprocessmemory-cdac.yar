rule TTP_XOR_WriteProcessMemory_cdac {
  strings:
    $key_cdac = { 9a de [2] a8 fc [2] ae c9 [2] 80 c9 [2] bf d5 }

  condition:
    any of them
}