rule TTP_XOR_QUAD_CurrentVersionRun_6a1c {
  strings:
    $key_6a1c = { 39 73 [2] 1d 7d [2] 36 51 [2] 18 73 [2] 0c 68 [2] 03 72 [2] 1d 6f [2] 1f 6e [2] 04 68 [2] 18 6f [2] 04 40 }

  condition:
    any of them
}