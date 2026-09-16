rule TTP_XOR_WriteProcessMemory_eb8e {
  strings:
    $key_eb8e = { bc fc [2] 8e de [2] 88 eb [2] a6 eb [2] 99 f7 }

  condition:
    any of them
}