rule TTP_XOR_WriteProcessMemory_538e {
  strings:
    $key_538e = { 04 fc [2] 36 de [2] 30 eb [2] 1e eb [2] 21 f7 }

  condition:
    any of them
}