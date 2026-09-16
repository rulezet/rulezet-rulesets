rule TTP_XOR_QUAD_CurrentVersionRun_683c {
  strings:
    $key_683c = { 3b 53 [2] 1f 5d [2] 34 71 [2] 1a 53 [2] 0e 48 [2] 01 52 [2] 1f 4f [2] 1d 4e [2] 06 48 [2] 1a 4f [2] 06 60 }

  condition:
    any of them
}