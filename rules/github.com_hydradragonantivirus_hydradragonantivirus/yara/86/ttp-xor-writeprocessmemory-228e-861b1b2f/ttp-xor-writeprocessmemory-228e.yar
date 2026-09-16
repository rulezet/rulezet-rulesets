rule TTP_XOR_WriteProcessMemory_228e {
  strings:
    $key_228e = { 75 fc [2] 47 de [2] 41 eb [2] 6f eb [2] 50 f7 }

  condition:
    any of them
}