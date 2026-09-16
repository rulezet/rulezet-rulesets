rule TTP_XOR_QUAD_CurrentVersionRun_5010 {
  strings:
    $key_5010 = { 03 7f [2] 27 71 [2] 0c 5d [2] 22 7f [2] 36 64 [2] 39 7e [2] 27 63 [2] 25 62 [2] 3e 64 [2] 22 63 [2] 3e 4c }

  condition:
    any of them
}