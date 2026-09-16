rule TTP_XOR_WriteProcessMemory_fcfc {
  strings:
    $key_fcfc = { ab 8e [2] 99 ac [2] 9f 99 [2] b1 99 [2] 8e 85 }

  condition:
    any of them
}