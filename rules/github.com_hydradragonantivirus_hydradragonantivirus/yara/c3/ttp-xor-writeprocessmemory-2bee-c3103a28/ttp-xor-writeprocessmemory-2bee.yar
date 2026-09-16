rule TTP_XOR_WriteProcessMemory_2bee {
  strings:
    $key_2bee = { 7c 9c [2] 4e be [2] 48 8b [2] 66 8b [2] 59 97 }

  condition:
    any of them
}