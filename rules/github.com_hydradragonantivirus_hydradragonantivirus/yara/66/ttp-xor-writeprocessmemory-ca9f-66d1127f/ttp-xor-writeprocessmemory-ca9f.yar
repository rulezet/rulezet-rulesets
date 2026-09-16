rule TTP_XOR_WriteProcessMemory_ca9f {
  strings:
    $key_ca9f = { 9d ed [2] af cf [2] a9 fa [2] 87 fa [2] b8 e6 }

  condition:
    any of them
}