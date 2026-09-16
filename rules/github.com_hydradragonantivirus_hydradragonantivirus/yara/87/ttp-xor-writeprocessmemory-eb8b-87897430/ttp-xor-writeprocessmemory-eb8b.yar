rule TTP_XOR_WriteProcessMemory_eb8b {
  strings:
    $key_eb8b = { bc f9 [2] 8e db [2] 88 ee [2] a6 ee [2] 99 f2 }

  condition:
    any of them
}