rule TTP_XOR_WriteProcessMemory_de9f {
  strings:
    $key_de9f = { 89 ed [2] bb cf [2] bd fa [2] 93 fa [2] ac e6 }

  condition:
    any of them
}