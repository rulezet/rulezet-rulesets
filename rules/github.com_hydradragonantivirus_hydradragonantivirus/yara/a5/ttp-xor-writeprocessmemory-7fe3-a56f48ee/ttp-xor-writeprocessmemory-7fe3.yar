rule TTP_XOR_WriteProcessMemory_7fe3 {
  strings:
    $key_7fe3 = { 28 91 [2] 1a b3 [2] 1c 86 [2] 32 86 [2] 0d 9a }

  condition:
    any of them
}