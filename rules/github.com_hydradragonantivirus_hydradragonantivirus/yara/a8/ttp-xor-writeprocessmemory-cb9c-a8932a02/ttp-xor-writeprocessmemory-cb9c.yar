rule TTP_XOR_WriteProcessMemory_cb9c {
  strings:
    $key_cb9c = { 9c ee [2] ae cc [2] a8 f9 [2] 86 f9 [2] b9 e5 }

  condition:
    any of them
}