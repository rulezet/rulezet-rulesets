rule TTP_XOR_QUAD_CurrentVersionRun_3b01 {
  strings:
    $key_3b01 = { 68 6e [2] 4c 60 [2] 67 4c [2] 49 6e [2] 5d 75 [2] 52 6f [2] 4c 72 [2] 4e 73 [2] 55 75 [2] 49 72 [2] 55 5d }

  condition:
    any of them
}