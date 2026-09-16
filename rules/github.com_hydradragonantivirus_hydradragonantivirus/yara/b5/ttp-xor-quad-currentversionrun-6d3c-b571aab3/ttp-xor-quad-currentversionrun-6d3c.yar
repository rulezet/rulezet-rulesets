rule TTP_XOR_QUAD_CurrentVersionRun_6d3c {
  strings:
    $key_6d3c = { 3e 53 [2] 1a 5d [2] 31 71 [2] 1f 53 [2] 0b 48 [2] 04 52 [2] 1a 4f [2] 18 4e [2] 03 48 [2] 1f 4f [2] 03 60 }

  condition:
    any of them
}