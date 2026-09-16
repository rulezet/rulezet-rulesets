rule TTP_XOR_WriteProcessMemory_0cbd {
  strings:
    $key_0cbd = { 5b cf [2] 69 ed [2] 6f d8 [2] 41 d8 [2] 7e c4 }

  condition:
    any of them
}