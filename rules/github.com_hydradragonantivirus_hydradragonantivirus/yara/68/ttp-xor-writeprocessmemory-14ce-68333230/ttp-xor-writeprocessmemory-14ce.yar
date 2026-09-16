rule TTP_XOR_WriteProcessMemory_14ce {
  strings:
    $key_14ce = { 43 bc [2] 71 9e [2] 77 ab [2] 59 ab [2] 66 b7 }

  condition:
    any of them
}