rule TTP_XOR_WriteProcessMemory_6cbd {
  strings:
    $key_6cbd = { 3b cf [2] 09 ed [2] 0f d8 [2] 21 d8 [2] 1e c4 }

  condition:
    any of them
}