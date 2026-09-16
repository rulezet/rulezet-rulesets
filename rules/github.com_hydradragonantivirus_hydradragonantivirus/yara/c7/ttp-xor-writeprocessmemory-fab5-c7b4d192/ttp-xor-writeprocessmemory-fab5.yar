rule TTP_XOR_WriteProcessMemory_fab5 {
  strings:
    $key_fab5 = { ad c7 [2] 9f e5 [2] 99 d0 [2] b7 d0 [2] 88 cc }

  condition:
    any of them
}