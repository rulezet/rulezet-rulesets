rule TTP_XOR_WriteProcessMemory_7cbd {
  strings:
    $key_7cbd = { 2b cf [2] 19 ed [2] 1f d8 [2] 31 d8 [2] 0e c4 }

  condition:
    any of them
}