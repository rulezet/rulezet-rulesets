rule TTP_XOR_QUAD_CurrentVersionRun_501c {
  strings:
    $key_501c = { 03 73 [2] 27 7d [2] 0c 51 [2] 22 73 [2] 36 68 [2] 39 72 [2] 27 6f [2] 25 6e [2] 3e 68 [2] 22 6f [2] 3e 40 }

  condition:
    any of them
}