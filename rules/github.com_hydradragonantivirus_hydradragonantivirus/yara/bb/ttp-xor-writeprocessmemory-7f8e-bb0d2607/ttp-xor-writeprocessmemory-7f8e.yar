rule TTP_XOR_WriteProcessMemory_7f8e {
  strings:
    $key_7f8e = { 28 fc [2] 1a de [2] 1c eb [2] 32 eb [2] 0d f7 }

  condition:
    any of them
}