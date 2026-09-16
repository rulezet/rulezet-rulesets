rule TTP_XOR_QUAD_CurrentVersionRun_653c {
  strings:
    $key_653c = { 36 53 [2] 12 5d [2] 39 71 [2] 17 53 [2] 03 48 [2] 0c 52 [2] 12 4f [2] 10 4e [2] 0b 48 [2] 17 4f [2] 0b 60 }

  condition:
    any of them
}