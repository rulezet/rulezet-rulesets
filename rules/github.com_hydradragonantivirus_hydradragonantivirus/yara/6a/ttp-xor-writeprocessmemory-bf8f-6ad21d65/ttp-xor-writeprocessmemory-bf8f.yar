rule TTP_XOR_WriteProcessMemory_bf8f {
  strings:
    $key_bf8f = { e8 fd [2] da df [2] dc ea [2] f2 ea [2] cd f6 }

  condition:
    any of them
}