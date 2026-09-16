rule TTP_XOR_WriteProcessMemory_1cbd {
  strings:
    $key_1cbd = { 4b cf [2] 79 ed [2] 7f d8 [2] 51 d8 [2] 6e c4 }

  condition:
    any of them
}