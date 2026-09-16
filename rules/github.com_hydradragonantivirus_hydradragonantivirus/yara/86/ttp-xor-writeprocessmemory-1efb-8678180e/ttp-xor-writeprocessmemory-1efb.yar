rule TTP_XOR_WriteProcessMemory_1efb {
  strings:
    $key_1efb = { 49 89 [2] 7b ab [2] 7d 9e [2] 53 9e [2] 6c 82 }

  condition:
    any of them
}