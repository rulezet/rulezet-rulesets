rule TTP_XOR_WriteProcessMemory_f89f {
  strings:
    $key_f89f = { af ed [2] 9d cf [2] 9b fa [2] b5 fa [2] 8a e6 }

  condition:
    any of them
}