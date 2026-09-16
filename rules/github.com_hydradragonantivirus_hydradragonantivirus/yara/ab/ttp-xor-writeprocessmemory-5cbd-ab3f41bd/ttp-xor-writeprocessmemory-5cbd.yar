rule TTP_XOR_WriteProcessMemory_5cbd {
  strings:
    $key_5cbd = { 0b cf [2] 39 ed [2] 3f d8 [2] 11 d8 [2] 2e c4 }

  condition:
    any of them
}