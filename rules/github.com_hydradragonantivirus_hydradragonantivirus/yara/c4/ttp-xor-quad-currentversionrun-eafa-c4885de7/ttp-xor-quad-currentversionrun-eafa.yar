rule TTP_XOR_QUAD_CurrentVersionRun_eafa {
  strings:
    $key_eafa = { b9 95 [2] 9d 9b [2] b6 b7 [2] 98 95 [2] 8c 8e [2] 83 94 [2] 9d 89 [2] 9f 88 [2] 84 8e [2] 98 89 [2] 84 a6 }

  condition:
    any of them
}