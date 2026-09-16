rule TTP_XOR_WriteProcessMemory_e3fc {
  strings:
    $key_e3fc = { b4 8e [2] 86 ac [2] 80 99 [2] ae 99 [2] 91 85 }

  condition:
    any of them
}