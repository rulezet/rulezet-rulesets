rule TTP_XOR_WriteProcessMemory_639f {
  strings:
    $key_639f = { 34 ed [2] 06 cf [2] 00 fa [2] 2e fa [2] 11 e6 }

  condition:
    any of them
}