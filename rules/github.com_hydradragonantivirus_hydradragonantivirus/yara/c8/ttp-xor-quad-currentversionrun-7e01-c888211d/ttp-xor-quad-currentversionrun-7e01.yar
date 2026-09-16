rule TTP_XOR_QUAD_CurrentVersionRun_7e01 {
  strings:
    $key_7e01 = { 2d 6e [2] 09 60 [2] 22 4c [2] 0c 6e [2] 18 75 [2] 17 6f [2] 09 72 [2] 0b 73 [2] 10 75 [2] 0c 72 [2] 10 5d }

  condition:
    any of them
}