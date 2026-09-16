rule TTP_XOR_WriteProcessMemory_c9cc {
  strings:
    $key_c9cc = { 9e be [2] ac 9c [2] aa a9 [2] 84 a9 [2] bb b5 }

  condition:
    any of them
}