rule TTP_XOR_QUAD_CurrentVersionRun_6522 {
  strings:
    $key_6522 = { 36 4d [2] 12 43 [2] 39 6f [2] 17 4d [2] 03 56 [2] 0c 4c [2] 12 51 [2] 10 50 [2] 0b 56 [2] 17 51 [2] 0b 7e }

  condition:
    any of them
}