rule TTP_XOR_WriteProcessMemory_3bee {
  strings:
    $key_3bee = { 6c 9c [2] 5e be [2] 58 8b [2] 76 8b [2] 49 97 }

  condition:
    any of them
}