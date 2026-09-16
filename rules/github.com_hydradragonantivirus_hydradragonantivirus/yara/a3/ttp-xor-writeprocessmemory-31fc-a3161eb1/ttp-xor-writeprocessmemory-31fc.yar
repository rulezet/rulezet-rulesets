rule TTP_XOR_WriteProcessMemory_31fc {
  strings:
    $key_31fc = { 66 8e [2] 54 ac [2] 52 99 [2] 7c 99 [2] 43 85 }

  condition:
    any of them
}