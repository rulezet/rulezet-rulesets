rule TTP_XOR_WriteProcessMemory_d8db {
  strings:
    $key_d8db = { 8f a9 [2] bd 8b [2] bb be [2] 95 be [2] aa a2 }

  condition:
    any of them
}