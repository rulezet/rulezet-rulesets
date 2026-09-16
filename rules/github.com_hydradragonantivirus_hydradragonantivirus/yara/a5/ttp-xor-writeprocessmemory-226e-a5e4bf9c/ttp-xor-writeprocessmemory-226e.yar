rule TTP_XOR_WriteProcessMemory_226e {
  strings:
    $key_226e = { 75 1c [2] 47 3e [2] 41 0b [2] 6f 0b [2] 50 17 }

  condition:
    any of them
}