rule TTP_XOR_WriteProcessMemory_7afb {
  strings:
    $key_7afb = { 2d 89 [2] 1f ab [2] 19 9e [2] 37 9e [2] 08 82 }

  condition:
    any of them
}