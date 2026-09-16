rule TTP_XOR_WriteProcessMemory_f4aa {
  strings:
    $key_f4aa = { a3 d8 [2] 91 fa [2] 97 cf [2] b9 cf [2] 86 d3 }

  condition:
    any of them
}