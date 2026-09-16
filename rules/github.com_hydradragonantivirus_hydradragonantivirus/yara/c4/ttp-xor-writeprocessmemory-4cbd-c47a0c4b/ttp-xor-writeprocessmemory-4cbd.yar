rule TTP_XOR_WriteProcessMemory_4cbd {
  strings:
    $key_4cbd = { 1b cf [2] 29 ed [2] 2f d8 [2] 01 d8 [2] 3e c4 }

  condition:
    any of them
}