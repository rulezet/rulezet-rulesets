rule TTP_XOR_WriteProcessMemory_61fc {
  strings:
    $key_61fc = { 36 8e [2] 04 ac [2] 02 99 [2] 2c 99 [2] 13 85 }

  condition:
    any of them
}