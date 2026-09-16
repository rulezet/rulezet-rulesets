rule TTP_XOR_WriteProcessMemory_4bee {
  strings:
    $key_4bee = { 1c 9c [2] 2e be [2] 28 8b [2] 06 8b [2] 39 97 }

  condition:
    any of them
}