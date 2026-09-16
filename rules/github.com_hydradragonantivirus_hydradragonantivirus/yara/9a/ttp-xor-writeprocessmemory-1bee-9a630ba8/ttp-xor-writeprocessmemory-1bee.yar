rule TTP_XOR_WriteProcessMemory_1bee {
  strings:
    $key_1bee = { 4c 9c [2] 7e be [2] 78 8b [2] 56 8b [2] 69 97 }

  condition:
    any of them
}