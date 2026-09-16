rule TTP_XOR_WriteProcessMemory_fcb6 {
  strings:
    $key_fcb6 = { ab c4 [2] 99 e6 [2] 9f d3 [2] b1 d3 [2] 8e cf }

  condition:
    any of them
}