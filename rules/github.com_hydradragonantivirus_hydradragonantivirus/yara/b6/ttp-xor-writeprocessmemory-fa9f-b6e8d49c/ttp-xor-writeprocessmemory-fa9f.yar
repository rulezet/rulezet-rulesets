rule TTP_XOR_WriteProcessMemory_fa9f {
  strings:
    $key_fa9f = { ad ed [2] 9f cf [2] 99 fa [2] b7 fa [2] 88 e6 }

  condition:
    any of them
}