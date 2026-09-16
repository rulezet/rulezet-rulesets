rule TTP_XOR_WriteProcessMemory_00fc {
  strings:
    $key_00fc = { 57 8e [2] 65 ac [2] 63 99 [2] 4d 99 [2] 72 85 }

  condition:
    any of them
}