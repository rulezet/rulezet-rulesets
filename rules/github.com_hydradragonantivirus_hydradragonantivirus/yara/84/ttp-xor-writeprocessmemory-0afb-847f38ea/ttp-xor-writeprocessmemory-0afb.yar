rule TTP_XOR_WriteProcessMemory_0afb {
  strings:
    $key_0afb = { 5d 89 [2] 6f ab [2] 69 9e [2] 47 9e [2] 78 82 }

  condition:
    any of them
}