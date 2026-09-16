rule TTP_XOR_WriteProcessMemory_226c {
  strings:
    $key_226c = { 75 1e [2] 47 3c [2] 41 09 [2] 6f 09 [2] 50 15 }

  condition:
    any of them
}