rule TTP_XOR_WriteProcessMemory_253e {
  strings:
    $key_253e = { 72 4c [2] 40 6e [2] 46 5b [2] 68 5b [2] 57 47 }

  condition:
    any of them
}