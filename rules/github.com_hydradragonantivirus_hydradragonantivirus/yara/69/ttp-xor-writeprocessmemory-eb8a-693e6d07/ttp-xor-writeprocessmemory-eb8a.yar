rule TTP_XOR_WriteProcessMemory_eb8a {
  strings:
    $key_eb8a = { bc f8 [2] 8e da [2] 88 ef [2] a6 ef [2] 99 f3 }

  condition:
    any of them
}