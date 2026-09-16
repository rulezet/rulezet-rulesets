rule TTP_XOR_WriteProcessMemory_f91b {
  strings:
    $key_f91b = { ae 69 [2] 9c 4b [2] 9a 7e [2] b4 7e [2] 8b 62 }

  condition:
    any of them
}