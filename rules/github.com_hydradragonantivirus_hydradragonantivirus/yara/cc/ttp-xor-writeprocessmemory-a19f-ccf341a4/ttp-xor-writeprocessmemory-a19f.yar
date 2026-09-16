rule TTP_XOR_WriteProcessMemory_a19f {
  strings:
    $key_a19f = { f6 ed [2] c4 cf [2] c2 fa [2] ec fa [2] d3 e6 }

  condition:
    any of them
}