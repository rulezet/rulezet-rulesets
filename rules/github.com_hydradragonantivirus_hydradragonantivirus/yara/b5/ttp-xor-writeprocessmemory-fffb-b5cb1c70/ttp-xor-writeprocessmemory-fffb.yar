rule TTP_XOR_WriteProcessMemory_fffb {
  strings:
    $key_fffb = { a8 89 [2] 9a ab [2] 9c 9e [2] b2 9e [2] 8d 82 }

  condition:
    any of them
}