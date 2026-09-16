rule TTP_XOR_WriteProcessMemory_fab2 {
  strings:
    $key_fab2 = { ad c0 [2] 9f e2 [2] 99 d7 [2] b7 d7 [2] 88 cb }

  condition:
    any of them
}