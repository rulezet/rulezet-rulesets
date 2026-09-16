rule TTP_XOR_WriteProcessMemory_5bee {
  strings:
    $key_5bee = { 0c 9c [2] 3e be [2] 38 8b [2] 16 8b [2] 29 97 }

  condition:
    any of them
}